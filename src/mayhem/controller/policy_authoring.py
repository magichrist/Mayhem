"""Plan 07 Phase 3 — the surface: authoring a policy and explaining its verdict.

Phases 1 and 2 built a vocabulary and put it inside the gate; Phase 4 sealed what
the gate decided. Between them sat a hole Phase 4 recorded and this phase closes:
**nothing authored, stored, or selected a bundle.** ``PolicyGateInputs`` existed,
was pure, and was constructed by nobody outside its own tests — so in production
every run still reached the gate with ``policy_gate=None`` and the older
``PolicyCfg`` block alone decided. A safety engine with no authoring surface is a
library, not a policy system.

Three things land here, and one deliberate absence.

**1. :func:`bundle_from_mapping` — authoring from a plain document.** A bundle is
read from a ``dict`` — YAML or JSON, whichever the caller loaded — with every
field named and every nested object validated, so a typo in a bundle is a typed
refusal naming the field rather than a ``ValidationError`` stack trace or, worse,
a silently dropped rule. It pins on the way out, so what gets published is
already digest-addressable.

**2. :class:`PolicyCatalog` — create, read, update, delete.** A frozen registry
whose every operation returns a new catalog, so a rejected publish cannot leave
a half-applied policy behind. Three rules it enforces, all default-deny:

* **A published version is immutable.** Re-publishing ``(id, version)`` with
  different content is refused, and so is publishing a version at or below one
  already published. This is what makes the pin meaningful: if a version could be
  rewritten in place, an approval bound to it would be approving something
  nobody can go back and read.
* **Deleting means retiring.** :meth:`PolicyCatalog.retire` tombstones a
  version rather than erasing it. An approval, an evidence record, or a replay
  from six weeks ago still names that version, and a registry that forgot it
  would make its own history unreadable. A retired version refuses to be
  resolved for a new run and keeps its digest on the record.
* **Resolution never silently substitutes.** :meth:`PolicyCatalog.resolve` with no
  version takes the newest published one and *says which* in
  :attr:`ResolvedPolicy.version`; with a version it takes that version or
  refuses. It never falls back.

Inheritance is deliberately **not** decided here. :meth:`PolicyCatalog.resolve`
builds the index from what is published and hands it over; a ``parents`` entry
that nothing published is then refused by
:func:`~mayhem.controller.policy_gate.detect_config_defect` as
``ConfigDefect.PARENT_MISSING``, with a remediation written for whoever wrote
the bundle. Two answers to "is this bundle resolvable" would be two places for a
regression to hide.

**3. :func:`explain_decision` and :func:`explain_refusal` — the explanation.** The
plan's acceptance is that the ``DENY`` block in its own text is produced by the
engine rather than hand-written, and it is: :func:`explain_decision` renders
exactly those four lines from a real
:class:`~mayhem.controller.policy_gate.PolicyGateResult`, the reason coming off
the deciding rule's own ``reason`` field and the ``Required`` line off the
requirements :func:`~mayhem.controller.policy_gate.required_approvals`
surfaced. :func:`explain_refusal` adds the promotion-refusal detail underneath:
every rule that was evaluated, what it observed, and what it wanted instead.

**The absence: nothing here writes.** There is no CLI group and no migration. The
catalog is an in-memory registry and this module performs no IO, so it owes no
``BOUNDARY_CALL_SITES`` row — see the module's own note at the end. What a
persisted policy store needs (a table, a migration number, a CLI surface) is
recorded as pending in the plan's Phase 3 ledger rather than invented here,
because :mod:`mayhem.infra.migrations` is not this phase's to edit and a policy
store with no CLI cannot be operated anyway.

What this module does NOT claim
-------------------------------

* **Not a second rule evaluator.** Every decision shown here was reached by
  :func:`~mayhem.controller.policy_gate.evaluate_gate`; this only reads its
  result and the same rules the gate read. :func:`explain_decision` refuses to
  invent a reason when it cannot name the rule that produced one.
* **Not an enforcement path.** :func:`explain_refusal` explains; it never
  refuses. The gate does.
* **Approval *levels* are still unbound to roles.** ``sre`` and
  ``service_owner`` are level strings a bundle names and a quorum counts; nothing
  here says which team satisfies which. :func:`format_required_approvals` maps a
  level to a display label and that is the whole of the mapping — a label, not a
  binding.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any

from mayhem.controller.policy_gate import (
    PolicyGateInputs,
    effective_compatibility,
    required_approvals,
)
from mayhem.domain.common import utc_now
from mayhem.domain.errors import DomainError, InvariantViolationError
from mayhem.domain.lowlevel_admission import collision_edges as lowlevel_collision_edges
from mayhem.domain.policy import (
    CompatibilityEdge,
    PolicyBundle,
    PolicyDimension,
    PolicyEffect,
    PolicyFacts,
    PolicyPredicate,
    PolicyRule,
    effective_rules,
    resolve_precedence,
)

if TYPE_CHECKING:
    from collections.abc import Sequence
    from datetime import datetime

    from mayhem.controller.policy_gate import PolicyGateResult, RequiredApproval
    from mayhem.domain.experiments import ExecutionPlan

__all__ = [
    "APPROVAL_LEVEL_LABELS",
    "PENDING_APPROVAL",
    "PolicyAuthoringError",
    "PolicyCatalog",
    "ResolvedPolicy",
    "amend_bundle",
    "approval_level_label",
    "builtin_collision_graph",
    "bundle_from_mapping",
    "explain_decision",
    "explain_refusal",
    "format_required_approvals",
    "with_pending_approvals",
]

# =============================================================================
# Vocabulary
# =============================================================================

#: The ``APPROVAL_LEVEL`` value a caller supplies to say "no approver has signed
#: this plan yet".
#:
#: It exists because :func:`~mayhem.controller.policy_gate.required_approvals`
#: only reports a requirement whose rule *matched* the facts, and an
#: ``approval_level in (sre, service_owner)`` rule cannot match an unheld level —
#: every level it names would then be dropped as already satisfied. The
#: authorable form of "these levels are still outstanding" is therefore
#: ``approval_level not_in (sre, service_owner)``, which needs a facts value to
#: be present for "not in" to mean anything. That value is this constant.
#:
#: It is a *fact value*, not a level: no quorum counts it, and
#: :func:`~mayhem.controller.approval_gate.quorum_from_requirements` never sees
#: it, because it counts distinct levels a bundle names rather than levels the
#: facts carry.
PENDING_APPROVAL = "unapproved"

#: Display labels for approval levels, used by :func:`format_required_approvals`.
#:
#: A label, not a binding. ``sre`` reads as ``SRE`` because that is how the
#: plan's own example spells it, and ``service_owner`` reads as two words because
#: that is how an operator says it. A level with no entry here is rendered as its
#: own authored spelling with underscores turned into spaces — an unknown level
#: is *shown*, never dropped and never guessed at, because a bundle is free to
#: name a level this table has never heard of.
APPROVAL_LEVEL_LABELS: dict[str, str] = {
    "sre": "SRE",
    "service_owner": "service owner",
    "security": "security",
    "manager": "manager",
}


def approval_level_label(level: str) -> str:
    """How an approval level is shown to a human. See :data:`APPROVAL_LEVEL_LABELS`."""
    label = APPROVAL_LEVEL_LABELS.get(level)
    if label is not None:
        return label
    return level.replace("_", " ") if level.strip() else level


def format_required_approvals(levels: Iterable[str]) -> str:
    """``"SRE + service owner"`` — the plan's example rendering of a quorum.

    De-duplicated and sorted so the same requirement set always renders the same
    string: an explanation is read by a person comparing two runs, and a
    rendering that reorders itself between them cannot be compared.
    """
    return " + ".join(approval_level_label(level) for level in sorted(set(levels)))


class PolicyAuthoringError(DomainError):
    """The authoring surface refused. Nothing was published."""


# =============================================================================
# Authoring a bundle from a document
# =============================================================================

#: Rule fields a bundle document may state. Everything else on a ``PolicyRule``
#: is derived (``rule_digest``) or absent from a document's vocabulary, and an
#: unknown key is refused rather than ignored: a misspelled ``remediation`` that
#: was silently dropped would leave an operator with a denial that has no fix.
_RULE_KEYS = frozenset(
    {
        "rule_id",
        "dimension",
        "predicate",
        "effect",
        "precedence",
        "reason",
        "remediation",
        "operator",
        "values",
    }
)
_BUNDLE_KEYS = frozenset(
    {
        "bundle_id",
        "version",
        "rules",
        "compatibility_edges",
        "parents",
        "default_effect",
        "created_at",
        "expires_at",
        "description",
        "content_digest",
    }
)
_EDGE_KEYS = frozenset(
    {"left_fault", "right_fault", "verdict", "reason", "conditions"}
)


def _as_mapping(value: Any, *, where: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        msg = f"{where} must be a mapping, got {type(value).__name__}"
        raise PolicyAuthoringError(msg)
    return value


def _reject_unknown(payload: Mapping[str, Any], allowed: frozenset[str], *, where: str) -> None:
    unknown = sorted(set(payload) - allowed)
    if unknown:
        msg = (
            f"{where} has unknown field(s) {unknown}; every field a document may "
            f"state is one of {sorted(allowed)}"
        )
        raise PolicyAuthoringError(msg)


def _rule_from_mapping(raw: Any, *, where: str) -> PolicyRule:
    """One ``PolicyRule`` from its document form, validated field by field."""
    payload = _as_mapping(raw, where=where)
    _reject_unknown(payload, _RULE_KEYS, where=where)
    if "rule_id" not in payload:
        msg = f"{where} has no rule_id; a rule nobody can name cannot be reported on"
        raise PolicyAuthoringError(msg)
    predicate_raw = payload.get("predicate")
    if predicate_raw is None:
        # Flat form: ``operator``/``values`` beside the rule rather than nested.
        if "operator" not in payload:
            msg = f"{where} states neither a predicate nor an operator"
            raise PolicyAuthoringError(msg)
        predicate_raw = {"operator": payload["operator"], "values": payload.get("values", ())}
    else:
        predicate_raw = _as_mapping(predicate_raw, where=f"{where}.predicate")
    try:
        predicate = PolicyPredicate(
            operator=predicate_raw["operator"],
            values=tuple(predicate_raw.get("values", ())),
        )
        return PolicyRule(
            rule_id=str(payload["rule_id"]),
            dimension=payload["dimension"],
            predicate=predicate,
            effect=payload.get("effect", PolicyEffect.DENY),
            precedence=int(payload.get("precedence", 0)),
            reason=str(payload.get("reason", "")),
            remediation=str(payload.get("remediation", "")),
        )
    except KeyError as exc:
        msg = f"{where} is missing the required field {exc.args[0]!r}"
        raise PolicyAuthoringError(msg) from exc
    except (InvariantViolationError, ValueError) as exc:
        # The primitives' own message, verbatim — an author reading "operator
        # 'in' requires at least one value" learns more than a paraphrase, and
        # the typed class it was raised as is not something a bundle document
        # should leak into a caller's error handling.
        raise PolicyAuthoringError(f"{where} is not a valid policy rule: {exc}") from exc


def _edge_from_mapping(raw: Any, *, where: str) -> CompatibilityEdge:
    payload = _as_mapping(raw, where=where)
    _reject_unknown(payload, _EDGE_KEYS, where=where)
    try:
        return CompatibilityEdge.model_validate(dict(payload))
    except (InvariantViolationError, ValueError, KeyError) as exc:
        raise PolicyAuthoringError(f"{where} is not a valid collision edge: {exc}") from exc


def bundle_from_mapping(
    raw: Mapping[str, Any], *, pin: bool = True, created_at: datetime | None = None
) -> PolicyBundle:
    """Build a validated, digest-pinned :class:`PolicyBundle` from a document.

    This is the whole of "policy CRUD"'s *create*: what an operator writes in
    YAML becomes a bundle whose every field has been checked and whose content
    digest is already set, so publishing it needs no second step and a later
    reader can re-derive exactly what was decided.

    ``pin=True`` — the default — is deliberate and is what makes an approval
    meaningful. An unpinned bundle computes its digest on demand, so two reads
    of "the same" document could disagree the moment an authoring tool rewrote
    a field. :meth:`PolicyBundle.pin` freezes the value the approval will name.

    The bundle's own validators are still the last word: this function shapes the
    document and turns their failures into typed, located refusals; it does not
    re-decide what a valid rule is.
    """
    document = _as_mapping(raw, where="policy bundle document")
    _reject_unknown(document, _BUNDLE_KEYS, where="policy bundle document")
    if "bundle_id" not in document:
        msg = "policy bundle document has no bundle_id; a policy nobody can name cannot be pinned"
        raise PolicyAuthoringError(msg)
    rules = tuple(
        _rule_from_mapping(entry, where=f"policy bundle rules[{index}]")
        for index, entry in enumerate(_as_sequence(document.get("rules", ()), where="rules"))
    )
    edges = tuple(
        _edge_from_mapping(entry, where=f"policy bundle compatibility_edges[{index}]")
        for index, entry in enumerate(
            _as_sequence(document.get("compatibility_edges", ()), where="compatibility_edges")
        )
    )
    payload: dict[str, Any] = {
        "bundle_id": str(document["bundle_id"]),
        "version": int(document.get("version", 1)),
        "rules": rules,
        "compatibility_edges": edges,
        "parents": tuple(str(parent) for parent in document.get("parents", ())),
        "default_effect": document.get("default_effect", PolicyEffect.DENY),
        "description": str(document.get("description", "")),
    }
    if "created_at" in document:
        payload["created_at"] = document["created_at"]
    elif created_at is not None:
        payload["created_at"] = created_at
    if "expires_at" in document:
        payload["expires_at"] = document["expires_at"]
    if "content_digest" in document:
        # Stated by the author, so it has to reach the constructor: the model's
        # validator compares the pin against the content, and building without it
        # returned a bundle whose digest was silently `None`. That is what this
        # branch used to do, while its comment claimed the comparison had already
        # happened — so every bundle read back out of a store carried no digest for
        # an approval to name. Passing it here also means a mismatch comes back
        # as a typed PolicyAuthoringError from the `try` below rather than as the
        # raw invariant.
        payload["content_digest"] = str(document["content_digest"])
    try:
        bundle = PolicyBundle(**payload)
    except (InvariantViolationError, ValueError) as exc:
        raise PolicyAuthoringError(f"policy bundle is not valid: {exc}") from exc
    if "content_digest" in document:
        # Already carried through `payload`, so the validator has compared it.
        return bundle
    return bundle.pin() if pin else bundle


def _as_sequence(value: Any, *, where: str) -> Sequence[Any]:
    if isinstance(value, str) or not isinstance(value, Iterable):
        msg = f"{where} must be a list of entries, got {type(value).__name__}"
        raise PolicyAuthoringError(msg)
    return list(value)


def amend_bundle(
    bundle: PolicyBundle,
    *,
    add: Iterable[PolicyRule] = (),
    drop: Iterable[str] = (),
    extra_edges: Iterable[CompatibilityEdge] = (),
    description: str | None = None,
    created_at: datetime | None = None,
    expires_at: datetime | None = None,
) -> PolicyBundle:
    """The *update* half of CRUD: the next version of ``bundle``.

    An update is a new version, never an edit in place, and that is the whole
    point. ``bundle`` is returned unchanged; the caller gets ``version + 1`` with
    the additions and removals applied, unpinned (so :meth:`PolicyBundle.pin` or
    :meth:`PolicyCatalog.publish` fixes the digest over the *new* content), and
    inheriting ``bundle``'s ``parents`` — an amendment of a layer is still a
    layer of the same base.

    A ``drop`` naming a rule the bundle does not have is refused rather than
    ignored: silently succeeding would leave an author believing their removal
    took effect.

    ``expires_at`` defaults to the previous version's window and is passed
    through explicitly, because a policy that inherits a window it has already
    outlived would refuse every run the moment it is published.
    """
    removed = tuple(drop)
    present = {rule.rule_id for rule in bundle.rules}
    unknown = sorted(rule_id for rule_id in removed if rule_id not in present)
    if unknown:
        msg = (
            f"cannot drop rule(s) {unknown} from {bundle.describe()}: the bundle does not "
            "declare them, and a removal that silently does nothing is worse than a refusal"
        )
        raise PolicyAuthoringError(msg)
    retained = tuple(rule for rule in bundle.rules if rule.rule_id not in set(removed))
    seen: set[str] = set()
    for rule in (*retained, *tuple(add)):
        if rule.rule_id in seen:
            msg = f"amended bundle declares rule {rule.rule_id!r} twice"
            raise PolicyAuthoringError(msg)
        seen.add(rule.rule_id)
    window = bundle.expires_at if expires_at is None else expires_at
    return PolicyBundle(
        bundle_id=bundle.bundle_id,
        version=bundle.version + 1,
        rules=(*retained, *tuple(add)),
        compatibility_edges=(*bundle.compatibility_edges, *tuple(extra_edges)),
        parents=bundle.parents,
        default_effect=bundle.default_effect,
        created_at=created_at or utc_now(),
        expires_at=window,
        description=bundle.description if description is None else description,
    )


# =============================================================================
# The collision graph the repository declares outside any bundle
# =============================================================================


def builtin_collision_graph() -> tuple[CompatibilityEdge, ...]:
    """Every collision edge another plan derives but does not register.

    Plan 04's gate derives fifteen edges from the low-level primitives' own
    ``incompatible_ids`` and, at the time of writing, registered them nowhere:
    ``domain/lowlevel_admission.py`` owns the derivation and
    :mod:`mayhem.domain.policy` owns the bundle, and neither could write into the
    other. This function is the join. It is called by
    :func:`baseline_bundle`, so publishing the baseline bundle registers the
    graph, and it is exposed so an operator composing their own bundle can add
    the same edges rather than re-derive them.

    **What registering them does and does not buy, stated exactly.**
    :func:`~mayhem.controller.policy_gate.check_compatibility` asks about
    ``PlannedFault.fault_id``. These fifteen edges are keyed by *primitive* ids
    (``io.read_delay``, ``kernel.syscall_latency``, …), and no id in the fault
    catalogue carries one of those names — the catalogue's ``clock.*`` members
    are ``clock.skew`` and ``clock.freeze``. So today the edges are consulted and
    find no matching pair: registering them is the missing wiring, not an
    immediately-live refusal. That is stated here rather than left for a reader
    to discover, and the moment a fault is named after a primitive the pair is
    already declared. The registry lives in the controller layer rather than in
    :mod:`mayhem.domain.policy` because ``lowlevel_admission`` imports ``policy``;
    a reverse import would close a cycle.
    """
    return lowlevel_collision_edges()


def baseline_bundle(
    *, bundle_id: str = "mayhem-baseline", created_at: datetime | None = None
) -> PolicyBundle:
    """A bundle that declares no rules and the repository's own collision graph.

    The migration target for "policy-as-code, starting from nothing": it denies
    nothing and allows nothing of its own (its ``default_effect`` is
    :attr:`~mayhem.domain.policy.PolicyEffect.DENY`, so a plan it is asked about
    is refused by the *default* rule unless a parent or an overlay speaks — that
    is the fail-closed default every bundle inherits, and the baseline bundle is
    where it is exercised) while contributing the fifteen edges plan 04 derived.

    It is pinned on the way out, so publishing it is one step and its digest is
    something an approval can name.
    """
    return PolicyBundle(
        bundle_id=bundle_id,
        version=1,
        rules=(),
        compatibility_edges=builtin_collision_graph(),
        default_effect=PolicyEffect.DENY,
        created_at=created_at or utc_now(),
        description=(
            "no authored rules; carries the collision graph the repository derives "
            "for itself, so a pair declared outside any bundle is still consulted"
        ),
    ).pin()


# =============================================================================
# The catalog
# =============================================================================


@dataclass(frozen=True)
class ResolvedPolicy:
    """The bundle a run should be decided under, and the index to resolve it with.

    ``index`` holds every other published bundle under its own id, which is what
    :func:`~mayhem.domain.policy.inherited_rules` resolves ``parents`` against. It
    deliberately contains *every* published bundle rather than only the
    ancestors: the walk is what enforces the ancestry, and a pre-filtered index
    would turn a dangling ``parents`` entry into an empty rule set rather than a
    refusal.
    """

    bundle: PolicyBundle
    index: Mapping[str, PolicyBundle]

    @property
    def bundle_id(self) -> str:
        return self.bundle.bundle_id

    @property
    def version(self) -> int:
        return self.bundle.version

    @property
    def digest(self) -> str:
        return self.bundle.compute_digest()

    def describe(self) -> str:
        return self.bundle.describe()


@dataclass(frozen=True)
class PolicyCatalog:
    """A versioned registry of policy bundles. Every operation returns a new one.

    Frozen, so a refused publish cannot half-apply and a caller that kept the old
    catalog kept the old policy — the same shape
    :class:`~mayhem.controller.approval_gate.ApprovalLedger` uses, for the same
    reason.

    Three invariants, each enforced here rather than by convention:

    * **immutability** — ``(bundle_id, version)`` is written once. Re-publishing
      it with different content, or publishing a version at or below one already
      out, is refused.
    * **retirement, not deletion** — :meth:`retire` tombstones. The digest
      survives so history stays readable.
    * **no silent substitution** — :meth:`resolve` takes the version named or
      refuses.
    """

    bundles: tuple[PolicyBundle, ...] = ()
    retired: tuple[tuple[str, int], ...] = ()
    #: Collision edges consulted on top of whatever the resolved bundle declares.
    #: ``()`` — the default — means the graph comes from the bundle alone.
    compatibility: tuple[CompatibilityEdge, ...] = ()

    def __len__(self) -> int:
        return len(self.bundles)

    def __contains__(self, key: object) -> bool:
        return isinstance(key, tuple) and len(key) == 2 and self._find(*key) is not None

    # -- create ---------------------------------------------------------------
    def publish(self, bundle: PolicyBundle) -> PolicyCatalog:
        """Add ``bundle``, pinned, and return the catalog that holds it.

        Raises:
            PolicyAuthoringError: If ``bundle`` is retired, if its content no
                longer matches its pin, if ``(id, version)`` is already held with
                different content, or if ``version`` is not above every version
                already published for that id.
        """
        if self.is_retired(bundle.bundle_id, bundle.version):
            msg = (
                f"policy version {bundle.describe()} was retired and cannot be republished; "
                "publish a new version instead — retirement exists so an approval or an "
                "evidence record that names this version can still be read"
            )
            raise PolicyAuthoringError(msg)
        try:
            bundle.verify_pin()
        except InvariantViolationError as exc:
            msg = (
                f"refusing to publish {bundle.describe()}: {exc}. A bundle whose content no "
                "longer matches its pin cannot be read back as the policy that decided "
                "anything"
            )
            raise PolicyAuthoringError(msg) from exc
        existing = self._find(bundle.bundle_id, bundle.version)
        if existing is not None:
            if existing.compute_digest() == bundle.compute_digest():
                # Idempotent re-publish. Not an error: an operator replaying the
                # same document should not have to know whether it landed.
                return self
            msg = (
                f"policy version {bundle.describe()} is already published with a different "
                f"content digest ({existing.compute_digest()[:12]} vs "
                f"{bundle.compute_digest()[:12]}); a published version is immutable, so an "
                "amendment is a new version"
            )
            raise PolicyAuthoringError(msg)
        published = tuple(sorted(self.bundles, key=_version_order) + [bundle.pin()])
        return replace(self, bundles=published)

    # -- read -----------------------------------------------------------------
    def versions(self, bundle_id: str) -> tuple[int, ...]:
        """Every published version of ``bundle_id``, ascending."""
        return tuple(
            sorted(bundle.version for bundle in self.bundles if bundle.bundle_id == bundle_id)
        )

    def latest(self, bundle_id: str) -> PolicyBundle | None:
        """The newest published version, or ``None`` when the id is unknown."""
        candidates = [bundle for bundle in self.bundles if bundle.bundle_id == bundle_id]
        return max(candidates, key=lambda bundle: bundle.version) if candidates else None

    def get(self, bundle_id: str, version: int) -> PolicyBundle:
        """One exact version.

        Raises:
            PolicyAuthoringError: If no such version is published — including when
                it *is* published but retired, which is a different message
                because the remedy is different.
        """
        found = self._find(bundle_id, version)
        if found is not None:
            return found
        if self.is_retired(bundle_id, version):
            msg = (
                f"policy version {bundle_id} v{version} was retired; a retired version may "
                "be read from history but cannot be resolved for a run"
            )
            raise PolicyAuthoringError(msg)
        known = self.versions(bundle_id)
        msg = (
            f"no policy version {bundle_id} v{version} is published"
            + (f"; published versions are {list(known)}" if known else f"; {bundle_id!r} is unknown")
        )
        raise PolicyAuthoringError(msg)

    def resolve(
        self, bundle_id: str, version: int | None = None, *, now: datetime | None = None
    ) -> ResolvedPolicy:
        """The bundle to decide under, and the index its ``parents`` resolve against.

        ``version=None`` takes the newest published version and says which in
        :attr:`ResolvedPolicy.version`. It does not take the newest *authorizing*
        one: expiry is :meth:`~mayhem.domain.policy.PolicyBundle.authorizes`'s
        question to answer, at the gate, with the run's own clock, and a registry
        that quietly reached past an expired version would make "which policy was
        this" depend on when the registry was asked rather than when the run
        happened.

        ``now`` is accepted and ignored by the current implementation, and is
        here so a caller can state the instant it is resolving for. It is *not*
        used to filter: see the paragraph above for why a filter here would be
        the wrong place.
        """
        del now  # documented above: expiry is the gate's question, not the registry's
        if version is None:
            newest = self.latest(bundle_id)
            if newest is None:
                raise PolicyAuthoringError(
                    f"no policy version for {bundle_id!r} is published; publish one before "
                    "resolving a run against it"
                )
            bundle = newest
        else:
            bundle = self.get(bundle_id, version)
        return ResolvedPolicy(
            bundle=bundle,
            index={other.bundle_id: other for other in self.bundles},
        )

    # -- delete ----------------------------------------------------------------
    def retire(self, bundle_id: str, version: int) -> PolicyCatalog:
        """Tombstone ``(bundle_id, version)``. See the class docstring for why.

        Retiring a version that is not published is refused rather than recorded:
        a tombstone for something nobody published asserts a history that did not
        happen, which is the same defect :func:`record_policy_bundle_change`
        refuses an unchanged "change" for.
        """
        if self._find(bundle_id, version) is None:
            msg = f"cannot retire {bundle_id} v{version}: no such version is published"
            raise PolicyAuthoringError(msg)
        return replace(self, retired=(*self.retired, (bundle_id, version)))

    def is_retired(self, bundle_id: str, version: int) -> bool:
        return (bundle_id, version) in self.retired

    # -- the gate seam ---------------------------------------------------------
    def gate_inputs(
        self,
        plan: ExecutionPlan,
        bundle_id: str,
        *,
        now: datetime,
        version: int | None = None,
        **overrides: Any,
    ) -> PolicyGateInputs:
        """Build :class:`PolicyGateInputs` for ``plan`` from this catalog.

        The seam that closes Phase 4's recorded gap: this is what constructs a
        ``PolicyGateInputs`` from a *selected, resolved, published* bundle, so a
        caller cannot decide a run under a bundle that was never published and
        therefore has no digest an approval could have named.

        ``plan`` is accepted and used for nothing but the caller's benefit of
        expressing the intent; the gate derives its facts from the plan itself.
        It is a parameter rather than an absence so the call site reads as what
        it is — "decide *this plan* under *this policy*" — and so a future
        budget-path derivation has the plan in hand without changing every call
        site. ``compatibility`` defaults to the catalog's own edges, which
        :func:`~mayhem.controller.policy_gate.effective_compatibility` then
        unions under the bundle's.
        """
        resolved = self.resolve(bundle_id, version, now=now)
        merged = dict(overrides)
        merged.setdefault("compatibility", self.compatibility)
        return PolicyGateInputs(
            bundle=resolved.bundle,
            now=now,
            index=resolved.index,
            **merged,
        )

    # -- internals --------------------------------------------------------------
    def _find(self, bundle_id: str, version: int) -> PolicyBundle | None:
        for bundle in self.bundles:
            if bundle.bundle_id == bundle_id and bundle.version == version:
                return bundle
        return None


def _version_order(bundle: PolicyBundle) -> tuple[str, int]:
    return (bundle.bundle_id, bundle.version)


# =============================================================================
# Approval requirements, as a caller supplies them
# =============================================================================


def with_pending_approvals(inputs: PolicyGateInputs) -> PolicyGateInputs:
    """``inputs`` with :data:`PENDING_APPROVAL` recorded as the observed level.

    The one caller-side thing a bundle's ``approval_level`` rules need and cannot
    supply for themselves. Without a value on that dimension, ``not_in`` rules
    cannot match (an unobserved dimension matches nothing) and ``in`` rules match
    only levels already held — so a bundle's approval requirements would be
    unreachable in both directions and the ``Required:`` line the plan's own
    example shows would never be produced.

    Derived dimensions still win: this only fills the one the gate cannot
    derive, exactly as any other ``observed`` entry does.
    """
    observed = dict(inputs.observed)
    observed[PolicyDimension.APPROVAL_LEVEL] = tuple(
        sorted({*observed.get(PolicyDimension.APPROVAL_LEVEL, ()), PENDING_APPROVAL})
    )
    return replace(inputs, observed=observed)


# =============================================================================
# Explanation
# =============================================================================


def _resolved_rules(
    result: PolicyGateResult, bundle: PolicyBundle | None, index: Mapping[str, PolicyBundle] | None
) -> tuple[PolicyRule, ...]:
    """The rules the gate read, in the order it read them.

    Returns ``()`` when the bundle cannot be resolved — the configuration-defect
    path, where no rule set was ever read. That emptiness is the reason the
    explanation below falls back to the defect's own reason rather than to
    ``PolicyRule.explain``: there is no rule to quote, and inventing one would be
    explaining a decision that was never made.
    """
    target = bundle if bundle is not None else result.bundle
    if target is None:
        return ()
    try:
        return resolve_precedence(effective_rules(target, index))
    except InvariantViolationError:
        return ()


def _reason_text(result: PolicyGateResult, rules: Sequence[PolicyRule]) -> str:
    """The reason a reader is shown, in the author's own words.

    Four sources, in order of how much they are trusted, and never a string
    surgery on a formatted refusal: the deciding rules' own ``reason`` field;
    then the configuration defect's verbatim message, when no rule set could be
    read at all; then a composed sentence for a default-effect decision, where
    no rule matched and there is nothing to quote; and only then the decision's
    own first reason, which is the last resort because it carries the trailing
    ``[rule-id]`` marker every internal refusal appends.

    The result of that last case is the one place a rule id can appear in a
    ``Reason:`` line, and it happens only when nothing better exists.
    """
    matched = set(result.decision.matched_rules)
    quoted = [
        (rule.reason or rule.explain(result.facts))
        for rule in rules
        if rule.rule_id in matched
    ]
    if quoted:
        return "; ".join(quoted)
    if result.config_defect is not None:
        return result.config_defect.reason
    bundle = result.decision.describe() if result.decision.bundle_id else "the policy set"
    if result.decision.denied:
        return f"no rule in {bundle} permits these facts; policy defaults to deny"
    return f"no rule in {bundle} forbids these facts; the policy's default effect is allow"


def _requirements(result: PolicyGateResult) -> tuple[RequiredApproval, ...]:
    return tuple(result.required_approvals)


def explain_decision(
    result: PolicyGateResult,
    *,
    plan_digest: str,
    bundle: PolicyBundle | None = None,
    index: Mapping[str, PolicyBundle] | None = None,
    plan_digest_chars: int = 6,
) -> str:
    """The verdict as four lines — the block plan 07 §"Example result" prints.

    ::

        DENY
        Reason: production policy forbids critical faults without two approvals.
        Required: SRE + service owner.
        Plan digest: abc123

    Produced by the engine from a real gate result, not written by hand: the
    headline is the gate's own verdict, the reason is the deciding rule's
    authored ``reason``, the ``Required`` line is whatever
    :func:`~mayhem.controller.policy_gate.required_approvals` surfaced, and the
    digest is the caller's, abbreviated because an explanation is read by a
    person and the full digest belongs in the evidence record.

    The ``Required`` line is omitted when nothing is outstanding, so an ALLOW
    with no outstanding requirements renders three lines and never a bare
    ``Required:`` — an explanation that names nothing is noise in an artifact a
    human is trying to read under pressure.

    ``bundle``/``index`` exist for the caller whose resolved bundle is not the
    one on the result (a catalog that resolved several ancestors). Omitting them
    is correct whenever ``result.bundle`` is set, which the gate always does.
    """
    lines = ["ALLOW" if result.allowed else "DENY"]
    lines.append(f"Reason: {_reason_text(result, _resolved_rules(result, bundle, index))}")
    levels = [approval.approval_level for approval in _requirements(result)]
    if levels:
        lines.append(f"Required: {format_required_approvals(levels)}.")
    lines.append(f"Plan digest: {plan_digest[:plan_digest_chars]}")
    return "\n".join(lines)


def explain_rules(
    result: PolicyGateResult,
    *,
    bundle: PolicyBundle | None = None,
    index: Mapping[str, PolicyBundle] | None = None,
) -> tuple[str, ...]:
    """One :meth:`~mayhem.domain.policy.PolicyRule.explain_detail` line per rule.

    Every rule that was *evaluated*, not only the ones that fired, so a reader
    can see what else was in the policy and what the plan satisfied — which is
    the half of an explanation that names only refusals never gives.
    """
    return tuple(rule.explain_detail(result.facts) for rule in _resolved_rules(result, bundle, index))


def explain_refusal(
    result: PolicyGateResult,
    *,
    plan_digest: str,
    bundle: PolicyBundle | None = None,
    index: Mapping[str, PolicyBundle] | None = None,
    plan_digest_chars: int = 6,
) -> str:
    """:func:`explain_decision` plus the rules behind it, in the promotion-refusal shape.

    Headline first, then every evaluated rule with what it observed, what it
    wanted instead, and — for a rule that fired — the remediation the author
    wrote for it. The remediation is included only when the author wrote one: a
    blank fix line is worse than none, because it looks like the fix is missing
    from the artifact rather than from the bundle.
    """
    rules = _resolved_rules(result, bundle, index)
    lines = explain_decision(
        result,
        plan_digest=plan_digest,
        bundle=bundle,
        index=index,
        plan_digest_chars=plan_digest_chars,
    ).splitlines()
    matched = set(result.decision.matched_rules)
    if not rules:
        return "\n".join(lines)
    lines.append("")
    lines.append(f"Rules ({len(rules)} evaluated, {len(matched)} matched):")
    for rule in rules:
        lines.append(f"  {rule.explain_detail(result.facts)}")
        if rule.rule_id in matched and rule.remediation:
            lines.append(f"    fix: {rule.remediation}")
    return "\n".join(lines)


def explain_facts(facts: PolicyFacts) -> str:
    """Every observed dimension, one per line, unobserved ones marked.

    The input half of an explanation, for a reader who needs to know what the
    gate was shown rather than what it concluded. ``<unobserved>`` is spelled
    out rather than omitted: an absent line would be indistinguishable from a
    dimension the gate never looks at, and those are different facts.
    """
    if not facts.values:
        return "<no dimensions observed>"
    return "\n".join(
        f"{dimension.value}: "
        + (", ".join(sorted(values)) if values else "<observed, empty>")
        for dimension, values in sorted(facts.values.items(), key=lambda item: item[0].value)
    )


def compatibility_inputs(inputs: PolicyGateInputs) -> tuple[CompatibilityEdge, ...]:
    """:func:`~mayhem.controller.policy_gate.effective_compatibility`, re-exported.

    Present so a surface that wants to *report* the graph — a ``mayhem policy
    explain`` listing "the pairs this policy forbids" — reads the merged graph the
    gate consults rather than one half of it.
    """
    return effective_compatibility(inputs)


def outstanding_requirements(
    result: PolicyGateResult, rules: Iterable[PolicyRule] | None = None
) -> tuple[RequiredApproval, ...]:
    """The requirements to show, from the result or re-derived from ``rules``.

    The result's own :attr:`~mayhem.controller.policy_gate.PolicyGateResult.
    required_approvals` is authoritative and is what a caller should read.
    Re-deriving from ``rules`` exists for the one case the result cannot cover: a
    caller holding rules but no gate result — a preview screen, a lint — where the
    question is the same and the answer must be the same function's.
    """
    if rules is None:
        return tuple(result.required_approvals)
    return required_approvals(rules, result.facts)
