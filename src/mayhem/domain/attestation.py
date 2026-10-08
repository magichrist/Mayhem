"""Attestations, provenance, and time as domain types (plan 12, Phase 1).

Phase 1 is types and pure arithmetic only. **Nothing here signs or verifies a
signature.** An :class:`AttestedEvent` is integrity-chained and named, never
authenticated: exactly the honesty rule :mod:`mayhem.domain.evidence_bundle`
already follows ("an unsigned bundle is reported as unsigned, never as
verified"). Signing, KMS/HSM custody, Sigstore, and WORM storage are Phase 2.

What this module owns
---------------------

* :class:`AttestedEvent` — canonical JSON bytes, SHA-256 content digest, and a
  hash-chain link to the predecessor's digest (gap 12's integrity half).
* :class:`AttestedTimestamp` — wall-clock *and* monotonic readings plus an
  uncertainty bound, so "which came first" is answerable even when the wall
  clock is unsynchronised (gap 98).
* :class:`ProvenanceEdge` / :class:`ProvenancePath` — the declared ladder
  ``fact → observation → probe → step → fault → target → experiment → verdict``
  with role labels on every hop (gap 99).
* :class:`Manifest` — event roots, signer identity, trust-root reference, and
  retention class (gap 57).

Canonicalization
----------------

:func:`canonical_event_json` is the one encoder for attested bytes. It follows
:mod:`mayhem.domain.hashing`'s conventions — sorted keys, no insignificant
whitespace, ``ensure_ascii=False`` — and adds three disciplines that an
attestation cannot do without:

* **Unicode NFC.** macOS filenames and hand-edited evidence arrive in both
  composed and decomposed spellings of the same text. NFC is applied to object
  keys *and* string values so equal text hashes equally.
* **No ``default=str``.** :func:`mayhem.domain.hashing.canonical_json` falls back
  to ``str(obj)`` for unknown types, which is lossy and therefore silently
  digestable. An attestation must refuse a payload it cannot represent exactly.
* **``allow_nan=False``.** ``NaN``/``Infinity`` are not JSON and would break a
  verifier written in another language; a reader must be able to interpret every
  number (same discipline as ``controller/steady_state.py``).

The divergence is deliberate and one-directional: for a payload that is plain
ASCII and already JSON-native, :func:`plain_digest` reproduces
:func:`mayhem.domain.hashing.digest` byte for byte, which is how an externally
computed plan digest (07/09 digests) enters a chain without a second convention.

Domain law
----------

No imports from ``toolkit``/``agents``/``controller``/``infra``, and no
``asyncio``/``socket``/``subprocess``/``sqlite3``/``pathlib``/``os`` — the
machine-checked "Domain layer has zero IO and no upward imports" contract in
``pyproject.toml``. ``hashlib`` is pure computation and is allowed, matching
:mod:`mayhem.domain.hashing` and :mod:`mayhem.domain.evidence_bundle`.
"""

from __future__ import annotations

import hashlib
import json
import math
import unicodedata
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from mayhem.domain.hashing import canonical_json, sha256_hex

if TYPE_CHECKING:
    from collections.abc import Sequence

ATTESTATION_SCHEMA_VERSION = "1.0"

#: The link a first-in-chain event points at when nothing precedes it.
GENESIS_DIGEST = ""


# --------------------------------------------------------------------------- #
# Canonicalization                                                            #
# --------------------------------------------------------------------------- #


def _normalize(value: Any, *, path: str = "$") -> Any:
    """Recursively NFC-normalize strings, rejecting non-JSON-native values.

    Raises:
        TypeError: If a value (or object key) has no exact JSON representation.
        ValueError: If a float is NaN or infinite.
    """
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"non-finite float at {path} is not attestable")
        return value
    if isinstance(value, dict):
        normalized: dict[str, Any] = {}
        for raw_key, raw_value in value.items():
            if not isinstance(raw_key, str):
                raise TypeError(f"object key at {path} must be str, got {type(raw_key).__name__}")
            key = unicodedata.normalize("NFC", raw_key)
            normalized[key] = _normalize(raw_value, path=f"{path}.{key}")
        return normalized
    if isinstance(value, (list, tuple)):
        return [_normalize(item, path=f"{path}[{index}]") for index, item in enumerate(value)]
    raise TypeError(f"value at {path} of type {type(value).__name__} is not JSON-native")


def canonical_event_json(value: Any) -> str:
    """Deterministic JSON text for attested bytes.

    Sorted keys, no insignificant whitespace, raw UTF-8, NFC-normalized,
    ``allow_nan=False``, and no lossy ``default`` fallback: two reordered but
    equal values produce identical strings, and a value that cannot be
    represented exactly raises instead of being stringified.
    """
    return json.dumps(
        _normalize(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def canonical_event_bytes(value: Any) -> bytes:
    """UTF-8 bytes of :func:`canonical_event_json`."""
    return canonical_event_json(value).encode("utf-8")


def content_digest(value: Any) -> str:
    """SHA-256 (hex) of the canonical bytes of ``value``."""
    return sha256_hex(canonical_event_json(value))


def plain_digest(value: Any) -> str:
    """Digest under the project-wide convention (:mod:`mayhem.domain.hashing`).

    Use this to fold an externally computed digest — a plan hash from 07, an
    approval digest from 09 — into an attested payload without minting a second
    convention. For plain ASCII JSON-native input it is byte-identical to
    :func:`content_digest`.
    """
    return sha256_hex(canonical_json(value))


def _require_hex_digest(value: str, field: str) -> str:
    if not value:
        return value
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise ValueError(f"{field} must be empty or a lowercase 64-char sha256 hex digest")
    return value


# --------------------------------------------------------------------------- #
# Time                                                                        #
# --------------------------------------------------------------------------- #


class TimeBasis(StrEnum):
    """Which reading an ordering claim rests on."""

    WALL_CLOCK = "wall_clock"
    MONOTONIC = "monotonic"


class AttestedTimestamp(BaseModel):
    """When an event happened, and how sure we are about it.

    Three readings, because no single clock is trustworthy on its own:

    * ``wall_clock`` — human-legible UTC instant, subject to NTP steps, VM clock
      drift, and suspension.
    * ``monotonic_ns`` — a non-decreasing reading from an arbitrary epoch, on
      the *same host*. Immune to wall-clock steps, meaningless across hosts.
    * ``uncertainty_ms`` — the half-width of the interval we claim the
      wall-clock reading is accurate to. ``0`` means "measured exactly", which
      is a claim a reader is entitled to distrust.

    ``wall_clock`` is normalized to UTC on the way in so two equal instants
    serialize identically regardless of the offset they were written with.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    wall_clock: datetime
    monotonic_ns: int = Field(ge=0)
    uncertainty_ms: float = Field(default=0.0, ge=0.0)
    source: str = "system"

    @field_validator("wall_clock")
    @classmethod
    def _require_aware_and_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
            raise ValueError("wall_clock must be timezone-aware")
        return value.astimezone(UTC)

    @field_validator("uncertainty_ms")
    @classmethod
    def _finite_uncertainty(cls, value: float) -> float:
        if not math.isfinite(value):
            raise ValueError("uncertainty_ms must be finite")
        return value

    @field_validator("source")
    @classmethod
    def _non_empty_source(cls, value: str) -> str:
        return unicodedata.normalize("NFC", value) if value else value

    @property
    def uncertainty(self) -> timedelta:
        """The half-width as a :class:`~datetime.timedelta`."""
        return timedelta(milliseconds=self.uncertainty_ms)

    @property
    def is_exact(self) -> bool:
        return self.uncertainty_ms == 0.0

    def earliest_wall_clock(self) -> datetime:
        """Earliest instant this reading can denote."""
        return self.wall_clock - self.uncertainty

    def latest_wall_clock(self) -> datetime:
        """Latest instant this reading can denote."""
        return self.wall_clock + self.uncertainty


@dataclass(frozen=True, slots=True)
class OrderedOffset:
    """A signed offset between two readings, with the bound that bounds it.

    ``seconds`` is ``other - reference`` using the nominal wall clocks.
    ``lower``/``upper`` are the extremes consistent with both uncertainty
    bounds: ``lower`` assumes the latest possible ``reference`` and the
    earliest possible ``other``, ``upper`` the reverse.

    ``ordering`` is the honest verdict: ``"before"``/``"after"`` only when the
    bounds prove it, ``"indeterminate"`` when they overlap.
    """

    seconds: float
    lower: float
    upper: float
    ordering: str

    @property
    def ordered(self) -> bool:
        return self.ordering in ("before", "after")

    def to_dict(self) -> dict[str, Any]:
        return {
            "seconds": self.seconds,
            "lower": self.lower,
            "upper": self.upper,
            "ordering": self.ordering,
        }


def wall_clock_offset(reference: AttestedTimestamp, other: AttestedTimestamp) -> OrderedOffset:
    """Bounded ``other - reference`` offset on the wall clock (pure)."""
    reference_worst_late = reference.latest_wall_clock()
    reference_worst_early = reference.earliest_wall_clock()
    lower = (other.earliest_wall_clock() - reference_worst_late).total_seconds()
    upper = (other.latest_wall_clock() - reference_worst_early).total_seconds()
    if upper < 0:
        ordering = "before"
    elif lower > 0:
        ordering = "after"
    else:
        ordering = "indeterminate"
    seconds = (other.wall_clock - reference.wall_clock).total_seconds()
    return OrderedOffset(seconds=seconds, lower=lower, upper=upper, ordering=ordering)


def wall_clock_ordering_ambiguous(reference: AttestedTimestamp, other: AttestedTimestamp) -> bool:
    """True when the uncertainty bounds overlap and the wall clock cannot order.

    When this is True, :func:`monotonic_ordering` is the honest fallback — but
    only for two readings taken on the same host.
    """
    return not wall_clock_offset(reference, other).ordered


def monotonic_ordering(reference: AttestedTimestamp, other: AttestedTimestamp) -> str:
    """Total order from monotonic readings: ``-1``/``0``/``1``.

    Monotonic clocks never step and never run backwards, so they order events
    strictly — including events whose wall clocks are identical or skewed.
    They say nothing about the *duration* between two events on different hosts,
    which is why :func:`wall_clock_offset` exists.
    """
    if other.monotonic_ns < reference.monotonic_ns:
        return "-1"
    if other.monotonic_ns > reference.monotonic_ns:
        return "1"
    return "0"


def monotonic_span_ns(first: AttestedTimestamp, last: AttestedTimestamp) -> int:
    """Elapsed monotonic nanoseconds from ``first`` to ``last``.

    Raises:
        ValueError: If the readings disagree with monotonic order.
    """
    span = last.monotonic_ns - first.monotonic_ns
    if span < 0:
        raise ValueError("monotonic readings run backwards: last precedes first")
    return span


def accumulated_uncertainty(samples: Sequence[AttestedTimestamp]) -> timedelta:
    """Worst-case accumulated wall-clock uncertainty over a sequence (pure).

    Sums the per-reading half-widths: the conservative bound a chain-closure
    claim may cite, since each reading can be wrong in the same direction.
    """
    return timedelta(milliseconds=sum(sample.uncertainty_ms for sample in samples))


# --------------------------------------------------------------------------- #
# Attested events                                                             #
# --------------------------------------------------------------------------- #


class EventIntegrityError(ValueError):
    """An attested event does not hash to what it says it hashes to."""


class AttestedEvent(BaseModel):
    """One attested fact: canonical bytes, SHA-256 digest, and a chain link.

    ``digest`` covers every other field, including ``previous_digest`` and the
    timestamp — so a later event's digest transitively covers every event
    before it. ``chain_link`` then binds this event to its predecessor:
    ``sha256({previous, event_id, digest})``, the same
    ``{previous, name, digest}`` shape
    :func:`mayhem.domain.evidence_bundle.build_bundle` uses, so a bundle chain
    and an attestation chain are read the same way.

    An event with an empty ``digest``/``chain_link`` is *unsealed*: its content
    digest is still computable, but nothing has claimed it. :func:`seal` fills
    both fields; :func:`verify_chain` refuses to call a chain valid while any
    member is unsealed.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = ATTESTATION_SCHEMA_VERSION
    event_id: str
    event_kind: str
    run_id: str
    sequence: int = Field(ge=0)
    payload: dict[str, Any] = Field(default_factory=dict)
    recorded_at: AttestedTimestamp
    previous_digest: str = GENESIS_DIGEST
    digest: str = ""
    chain_link: str = ""
    redaction_policy: str = ""

    @field_validator("event_id", "event_kind", "run_id")
    @classmethod
    def _non_empty(cls, value: str) -> str:
        normalized = unicodedata.normalize("NFC", value)
        if not normalized.strip():
            raise ValueError("event_id, event_kind and run_id must be non-empty")
        return normalized

    @field_validator("previous_digest", "digest", "chain_link")
    @classmethod
    def _hex_digest(cls, value: str) -> str:
        return _require_hex_digest(value, "attested digest")

    @field_validator("payload")
    @classmethod
    def _canonicalizable(cls, value: dict[str, Any]) -> dict[str, Any]:
        try:
            canonical_event_json(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"payload is not attestable JSON: {exc}") from exc
        return value

    # -- canonical form ----------------------------------------------------- #

    def canonical_view(self) -> dict[str, Any]:
        """The hashed view: every field except the two that state the hash."""
        view = self.model_dump(mode="json")
        view.pop("digest", None)
        view.pop("chain_link", None)
        return view

    def canonical_bytes(self) -> bytes:
        """Canonical UTF-8 bytes this event attests to."""
        return canonical_event_bytes(self.canonical_view())

    def computed_digest(self) -> str:
        """SHA-256 of :meth:`canonical_bytes`."""
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def computed_chain_link(self) -> str:
        """The chain link this event carries or would carry.

        Uses the declared digest when present, else the computed one, so an
        unsealed event still has a well-defined expected link.
        """
        return content_digest(
            {
                "previous": self.previous_digest,
                "event_id": self.event_id,
                "digest": self.digest or self.computed_digest(),
            }
        )

    # -- sealing ------------------------------------------------------------ #

    @property
    def is_sealed(self) -> bool:
        return bool(self.digest and self.chain_link)

    @property
    def is_genesis(self) -> bool:
        return self.previous_digest == GENESIS_DIGEST

    def seal(self) -> AttestedEvent:
        """Return a copy carrying its computed digest and chain link."""
        sealed = self.model_copy(update={"digest": self.computed_digest()})
        return sealed.model_copy(update={"chain_link": sealed.computed_chain_link()})

    def with_previous_digest(self, previous_digest: str) -> AttestedEvent:
        """Return a copy linked to ``previous_digest`` (still unsealed)."""
        checked = _require_hex_digest(previous_digest, "previous_digest")
        return self.model_copy(update={"previous_digest": checked})

    def digest_matches(self) -> bool:
        """True when a declared digest equals the digest of the content."""
        return self.is_sealed and self.digest == self.computed_digest()

    def chain_link_matches(self) -> bool:
        """True when a declared chain link equals the expected link."""
        return self.is_sealed and self.chain_link == self.computed_chain_link()

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


def seal_events(
    events: Sequence[AttestedEvent], previous_digest: str = GENESIS_DIGEST
) -> tuple[AttestedEvent, ...]:
    """Seal ``events`` in order, wiring each link to its predecessor (pure).

    Each event keeps its own content; only ``previous_digest``, ``digest`` and
    ``chain_link`` are computed. The returned chain's last
    :func:`chain_root` is the root to record in a :class:`Manifest`.

    Raises:
        ValueError: If ``previous_digest`` is malformed.
    """
    running = _require_hex_digest(previous_digest, "previous_digest")
    sealed: list[AttestedEvent] = []
    for event in events:
        linked = event.with_previous_digest(running).seal()
        running = linked.chain_link
        sealed.append(linked)
    return tuple(sealed)


def chain_root(events: Sequence[AttestedEvent]) -> str:
    """The last event's chain link — the root a manifest commits to."""
    return events[-1].chain_link if events else GENESIS_DIGEST


# --------------------------------------------------------------------------- #
# Chain verification                                                          #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class ChainVerification:
    """The verdict on a chain, with every failure naming its event."""

    valid: bool
    checked: int = 0
    errors: tuple[str, ...] = ()
    root_digest: str = GENESIS_DIGEST

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "checked": self.checked,
            "errors": list(self.errors),
            "root_digest": self.root_digest,
        }


def _short(digest: str) -> str:
    """Digest prefix for error text — 12 hex chars, never the whole value."""
    return digest[:12] if digest else "<none>"


def _check_event_integrity(event: AttestedEvent) -> list[str]:
    """Schema, seal state, and self-consistency of a single event."""
    if event.schema_version != ATTESTATION_SCHEMA_VERSION:
        return [
            f"event {event.event_id!r} has unsupported schema "
            f"{event.schema_version!r} (supported: {ATTESTATION_SCHEMA_VERSION})"
        ]
    if not event.is_sealed:
        return [f"event {event.event_id!r} is unsealed: digest and chain link are empty"]

    errors: list[str] = []
    computed = event.computed_digest()
    if event.digest != computed:
        errors.append(
            f"event {event.event_id!r} content digest mismatch: "
            f"declared {_short(event.digest)}, computed {_short(computed)}"
        )
    expected_link = event.computed_chain_link()
    if event.chain_link != expected_link:
        errors.append(
            f"event {event.event_id!r} chain link mismatch: "
            f"declared {_short(event.chain_link)}, computed {_short(expected_link)}"
        )
    return errors


def _check_link(event: AttestedEvent, predecessor: AttestedEvent | None) -> list[str]:
    """Link to the predecessor: digest, sequence order, and run continuity."""
    if predecessor is None:
        if event.sequence == 0 and event.previous_digest != GENESIS_DIGEST:
            return [
                f"event {event.event_id!r} starts a chain but links to "
                f"{_short(event.previous_digest)}"
            ]
        return []

    errors: list[str] = []
    if event.previous_digest != predecessor.chain_link:
        errors.append(
            f"event {event.event_id!r} does not link to predecessor "
            f"{predecessor.event_id!r}: expected "
            f"{_short(predecessor.chain_link)}, found {_short(event.previous_digest)}"
        )
    if event.sequence <= predecessor.sequence:
        errors.append(
            f"event {event.event_id!r} sequence {event.sequence} does not follow "
            f"predecessor {predecessor.event_id!r} sequence {predecessor.sequence}"
        )
    if event.run_id != predecessor.run_id:
        errors.append(
            f"event {event.event_id!r} belongs to run {event.run_id!r}, "
            f"predecessor {predecessor.event_id!r} to {predecessor.run_id!r}"
        )
    return errors


def verify_chain(events: Sequence[AttestedEvent]) -> ChainVerification:
    """Verify a chain offline: order, per-event digest, and link to predecessor.

    Every error names the offending ``event_id`` so an auditor can go straight
    to it. No store, no cluster, no control plane — the input is the events'
    own bytes.
    """
    errors: list[str] = []
    seen: set[str] = set()
    predecessor: AttestedEvent | None = None

    for event in events:
        if event.event_id in seen:
            errors.append(f"duplicate event {event.event_id!r} in chain")
        seen.add(event.event_id)

        errors.extend(_check_event_integrity(event))
        errors.extend(_check_link(event, predecessor))
        predecessor = event

    return ChainVerification(
        valid=not errors,
        checked=len(events),
        errors=tuple(errors),
        root_digest=chain_root(events),
    )


# --------------------------------------------------------------------------- #
# Provenance                                                                  #
# --------------------------------------------------------------------------- #


class ProvenanceNodeKind(StrEnum):
    """The declared ladder's node kinds, in ladder order."""

    FACT = "fact"
    OBSERVATION = "observation"
    PROBE = "probe"
    STEP = "step"
    FAULT = "fault"
    TARGET = "target"
    EXPERIMENT = "experiment"
    VERDICT = "verdict"


#: The declared provenance ladder, in order (plan 12 Phase 1, gap 99). Every
#: :class:`ProvenanceEdge` must ascend this order.
PROVENANCE_LADDER: tuple[ProvenanceNodeKind, ...] = (
    ProvenanceNodeKind.FACT,
    ProvenanceNodeKind.OBSERVATION,
    ProvenanceNodeKind.PROBE,
    ProvenanceNodeKind.STEP,
    ProvenanceNodeKind.FAULT,
    ProvenanceNodeKind.TARGET,
    ProvenanceNodeKind.EXPERIMENT,
    ProvenanceNodeKind.VERDICT,
)

_LADDER_INDEX: dict[ProvenanceNodeKind, int] = {
    kind: index for index, kind in enumerate(PROVENANCE_LADDER)
}


class ProvenanceRole(StrEnum):
    """Why one node points at another.

    Roles are labels, not graph semantics: the ladder order is enforced, the
    label is free within the vocabulary. A reader can therefore ask "what
    exactly does this edge claim?" without the type system answering for them.
    """

    PRODUCED = "produced"
    MEASURED = "measured"
    DERIVED_FROM = "derived_from"
    ATTRIBUTED_TO = "attributed_to"
    APPLIED_BY = "applied_by"
    AGGREGATED_INTO = "aggregated_into"
    SUMMARIZED_BY = "summarized_by"
    SUPPORTED_BY = "supported_by"


class ProvenanceRef(BaseModel):
    """A pointer at one node of the provenance ladder."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: ProvenanceNodeKind
    id: str

    @field_validator("id")
    @classmethod
    def _non_empty(cls, value: str) -> str:
        normalized = unicodedata.normalize("NFC", value)
        if not normalized.strip():
            raise ValueError("provenance node id must be non-empty")
        return normalized

    @property
    def ladder_index(self) -> int:
        return _LADDER_INDEX[self.kind]

    def key(self) -> str:
        """Canonical, store-safe reference key."""
        return f"{self.kind.value}:{self.id}"

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


class ProvenanceEdge(BaseModel):
    """A directed, role-labelled hop up the ladder.

    The ladder order is the law: a hop may only move *upward*
    (``fact → … → verdict``). A reversed or lateral hop is rejected at
    construction, so an ill-formed graph cannot be built and later "corrected".
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    source: ProvenanceRef
    target: ProvenanceRef
    role: ProvenanceRole = ProvenanceRole.DERIVED_FROM
    note: str = ""

    @model_validator(mode="after")
    def _ascends_the_ladder(self) -> ProvenanceEdge:
        if self.source.ladder_index >= self.target.ladder_index:
            raise ValueError(
                f"provenance edge must ascend the ladder "
                f"({PROVENANCE_LADDER[self.source.ladder_index].value} → "
                f"{PROVENANCE_LADDER[self.target.ladder_index].value}), "
                f"got {self.source.key()} → {self.target.key()}"
            )
        return self

    def label(self) -> str:
        """Human-readable edge, for audit output."""
        return f"{self.source.key()} -{self.role.value}-> {self.target.key()}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source.to_dict(),
            "target": self.target.to_dict(),
            "role": self.role.value,
            "note": self.note,
        }


class ProvenancePath(BaseModel):
    """An ordered chain of :class:`ProvenanceEdge` — one hop per rung.

    :meth:`ladder` builds the full eight-rung path; :meth:`is_complete` is the
    predicate an auditor asserts on, and it names the first rung that is
    missing or out of order.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    edges: tuple[ProvenanceEdge, ...] = ()

    @classmethod
    def ladder(
        cls,
        nodes: Sequence[ProvenanceRef],
        *,
        role: ProvenanceRole = ProvenanceRole.DERIVED_FROM,
    ) -> ProvenancePath:
        """Build the canonical path from eight refs, one per rung.

        Raises:
            ValueError: If ``nodes`` is not exactly the ladder in order.
        """
        refs = tuple(nodes)
        if len(refs) != len(PROVENANCE_LADDER):
            raise ValueError(
                f"a provenance ladder needs {len(PROVENANCE_LADDER)} nodes "
                f"({' → '.join(kind.value for kind in PROVENANCE_LADDER)}), got {len(refs)}"
            )
        expected = [ref.kind for ref in refs]
        if expected != list(PROVENANCE_LADDER):
            raise ValueError(
                f"provenance nodes must be in ladder order, got "
                f"{' → '.join(kind.value for kind in expected)}"
            )
        return cls(
            edges=tuple(
                ProvenanceEdge(source=refs[index], target=refs[index + 1], role=role)
                for index in range(len(refs) - 1)
            )
        )

    def kinds(self) -> tuple[ProvenanceNodeKind, ...]:
        """The rung kinds this path touches, in order."""
        if not self.edges:
            return ()
        return (self.edges[0].source.kind, *(edge.target.kind for edge in self.edges))

    def nodes(self) -> tuple[ProvenanceRef, ...]:
        """Every node the path touches, in order, without duplicates."""
        if not self.edges:
            return ()
        return (self.edges[0].source, *(edge.target for edge in self.edges))

    def errors(self) -> tuple[str, ...]:
        """Why this path is not a complete ladder traversal, if it is not."""
        problems: list[str] = []
        kinds = self.kinds()
        if kinds != PROVENANCE_LADDER:
            problems.append(
                f"path rungs {' → '.join(kind.value for kind in kinds)} do not equal the "
                f"declared ladder {' → '.join(kind.value for kind in PROVENANCE_LADDER)}"
            )
        for index, edge in enumerate(self.edges):
            if index and edge.source != self.edges[index - 1].target:
                problems.append(
                    f"edge {index} starts at {edge.source.key()} but edge {index - 1} "
                    f"ends at {self.edges[index - 1].target.key()}"
                )
        ids = [node.id for node in self.nodes()]
        duplicates = sorted({node_id for node_id in ids if ids.count(node_id) > 1})
        if duplicates:
            problems.append(f"path reuses node id(s) {', '.join(duplicates)}")
        return tuple(problems)

    def is_complete(self) -> bool:
        """True when the path walks the whole declared ladder exactly once."""
        return not self.errors()

    def to_dict(self) -> dict[str, Any]:
        return {"edges": [edge.to_dict() for edge in self.edges]}


# --------------------------------------------------------------------------- #
# Manifest                                                                    #
# --------------------------------------------------------------------------- #


class RetentionClass(StrEnum):
    """How long evidence may live (gap 57).

    Phase 1 only *names* the class; Phase 2 enforces the hot → cold → archive →
    legal-hold-aware-delete ladder. ``LEGAL_HOLD`` is a class rather than a flag
    because "never delete" is the strongest possible retention promise and must
    survive a policy edit as a value.
    """

    EPHEMERAL = "ephemeral"
    HOT = "hot"
    COLD = "cold"
    ARCHIVE = "archive"
    LEGAL_HOLD = "legal_hold"


class Manifest(BaseModel):
    """What a set of attested events commits to, and who is responsible for it.

    ``event_ids`` and ``event_roots`` are parallel tuples — the digest of each
    covered event, in order — so an auditor can tell *which* event a root
    belongs to without replaying the chain.

    ``signer_identity`` and ``trust_root_ref`` are the honesty gate of plan 12
    Phase 6 ("every signing claim names the key holder and trust root"). Phase 1
    signs nothing: with ``signer_identity`` empty, :func:`verify_manifest`
    reports *unsigned* as a warning and never as verified authorship.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = ATTESTATION_SCHEMA_VERSION
    manifest_id: str
    run_id: str
    event_ids: tuple[str, ...] = ()
    event_roots: tuple[str, ...] = ()
    signer_identity: str = ""
    trust_root_ref: str = ""
    retention_class: RetentionClass = RetentionClass.HOT
    created_at: AttestedTimestamp | None = None
    previous_manifest_digest: str = GENESIS_DIGEST
    manifest_digest: str = ""

    @field_validator("manifest_id", "run_id")
    @classmethod
    def _non_empty(cls, value: str) -> str:
        normalized = unicodedata.normalize("NFC", value)
        if not normalized.strip():
            raise ValueError("manifest_id and run_id must be non-empty")
        return normalized

    @field_validator("event_ids")
    @classmethod
    def _unique_event_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(unicodedata.normalize("NFC", item) for item in value)
        if len(set(normalized)) != len(normalized):
            raise ValueError("manifest event_ids must be unique")
        return normalized

    @field_validator("event_roots")
    @classmethod
    def _hex_roots(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(_require_hex_digest(item, "event root") for item in value)

    @field_validator("previous_manifest_digest", "manifest_digest")
    @classmethod
    def _hex_digest(cls, value: str) -> str:
        return _require_hex_digest(value, "manifest digest")

    @model_validator(mode="after")
    def _parallel_roots(self) -> Manifest:
        if self.event_ids and len(self.event_ids) != len(self.event_roots):
            raise ValueError(
                f"manifest covers {len(self.event_ids)} event ids but {len(self.event_roots)} roots"
            )
        return self

    @property
    def signed(self) -> bool:
        """Whether a signer is named. Phase 1 mints no signature bytes."""
        return bool(self.signer_identity)

    @property
    def covered_events(self) -> int:
        return len(self.event_ids)

    def canonical_view(self) -> dict[str, Any]:
        """The hashed view: every field except the one stating the hash."""
        view = self.model_dump(mode="json")
        view.pop("manifest_digest", None)
        return view

    def computed_digest(self) -> str:
        """SHA-256 of the manifest's canonical bytes."""
        return content_digest(self.canonical_view())

    def seal(self) -> Manifest:
        """Return a copy carrying its computed digest."""
        return self.model_copy(update={"manifest_digest": self.computed_digest()})

    def digest_matches(self) -> bool:
        return bool(self.manifest_digest) and self.manifest_digest == self.computed_digest()

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


def build_manifest(
    events: Sequence[AttestedEvent],
    *,
    manifest_id: str,
    run_id: str = "",
    signer_identity: str = "",
    trust_root_ref: str = "",
    retention_class: RetentionClass = RetentionClass.HOT,
    created_at: AttestedTimestamp | None = None,
    previous_manifest_digest: str = GENESIS_DIGEST,
) -> Manifest:
    """Seal a manifest over ``events``' digests, in order (pure).

    Raises:
        ValueError: If any event is unsealed — a manifest must not commit to a
            digest nobody has computed.
    """
    unsealed = [event.event_id for event in events if not event.is_sealed]
    if unsealed:
        raise ValueError(f"cannot build a manifest over unsealed event(s): {', '.join(unsealed)}")
    return Manifest(
        manifest_id=manifest_id,
        run_id=run_id or (events[0].run_id if events else ""),
        event_ids=tuple(event.event_id for event in events),
        event_roots=tuple(event.digest for event in events),
        signer_identity=signer_identity,
        trust_root_ref=trust_root_ref,
        retention_class=retention_class,
        created_at=created_at,
        previous_manifest_digest=previous_manifest_digest,
    ).seal()


@dataclass(frozen=True, slots=True)
class ManifestVerification:
    """The manifest verdict, with every reason spelled out."""

    valid: bool
    signed: bool
    events_checked: int = 0
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    manifest_digest: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "signed": self.signed,
            "events_checked": self.events_checked,
            "errors": list(self.errors),
            "warnings": list(self.warnings),
            "manifest_digest": self.manifest_digest,
        }


def _check_signer_honesty(manifest: Manifest) -> tuple[list[str], list[str]]:
    """The plan 12 Phase 6 gate: a signing claim must name whom *and* what trust.

    Returns ``(errors, warnings)``. An unnamed signer is a warning, never a
    pass — the same rule the evidence bundle follows.
    """
    errors: list[str] = []
    warnings: list[str] = []
    if manifest.signed and not manifest.trust_root_ref:
        errors.append(
            f"manifest {manifest.manifest_id!r} names signer "
            f"{manifest.signer_identity!r} but no trust root"
        )
    if manifest.trust_root_ref and not manifest.signed:
        errors.append(
            f"manifest {manifest.manifest_id!r} names trust root "
            f"{manifest.trust_root_ref!r} but no signer"
        )
    if not manifest.signed:
        warnings.append("manifest is unsigned: integrity is verified, authorship is not")
    return errors, warnings


def _check_coverage(manifest: Manifest, events: Sequence[AttestedEvent]) -> list[str]:
    """The manifest's roots must be the supplied events' roots, in order."""
    errors: list[str] = []
    if len(events) != manifest.covered_events:
        errors.append(
            f"manifest {manifest.manifest_id!r} covers {manifest.covered_events} events, "
            f"{len(events)} supplied"
        )
    for index, event in enumerate(events):
        if index >= len(manifest.event_ids) or index >= len(manifest.event_roots):
            break
        if manifest.event_ids[index] != event.event_id:
            errors.append(
                f"manifest {manifest.manifest_id!r} event {index} is "
                f"{manifest.event_ids[index]!r}, supplied {event.event_id!r}"
            )
        if manifest.event_roots[index] != event.digest:
            errors.append(
                f"manifest {manifest.manifest_id!r} root for event "
                f"{event.event_id!r} mismatch: declared "
                f"{_short(manifest.event_roots[index])}, computed {_short(event.digest)}"
            )
    return errors


def verify_manifest(
    manifest: Manifest, events: Sequence[AttestedEvent] | None = None
) -> ManifestVerification:
    """Verify a manifest offline, optionally against the events it covers.

    Checks the manifest's own digest, the alignment of ``event_ids``/
    ``event_roots``, the honesty of the signer fields, and — when ``events``
    are supplied — the chain itself. Authorship is *never* claimed: an unnamed
    signer yields a warning, not a pass.
    """
    errors: list[str] = []
    warnings: list[str] = []

    if manifest.schema_version != ATTESTATION_SCHEMA_VERSION:
        errors.append(
            f"unsupported manifest schema {manifest.schema_version!r} "
            f"(supported: {ATTESTATION_SCHEMA_VERSION})"
        )

    if not manifest.digest_matches():
        computed = manifest.computed_digest()
        errors.append(
            f"manifest {manifest.manifest_id!r} digest mismatch: "
            f"declared {_short(manifest.manifest_digest)}, computed {_short(computed)}"
        )

    signer_errors, signer_warnings = _check_signer_honesty(manifest)
    errors.extend(signer_errors)
    warnings.extend(signer_warnings)

    if events is not None:
        errors.extend(verify_chain(events).errors)
        errors.extend(_check_coverage(manifest, events))
    elif not manifest.covered_events:
        warnings.append(f"manifest {manifest.manifest_id!r} covers no events")

    return ManifestVerification(
        valid=not errors,
        signed=manifest.signed,
        events_checked=len(events) if events is not None else 0,
        errors=tuple(errors),
        warnings=tuple(warnings),
        manifest_digest=manifest.manifest_digest,
    )
