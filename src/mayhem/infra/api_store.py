"""Control-plane persistence for the API resource vocabulary (plan 08, Phase 2).

Phase 1 (:mod:`mayhem.domain.api`) made the *vocabulary*: nine resource types
that each **contain** their domain object and re-derive every identity field
from it, so a resource that could disagree with its own source is not a bug
class here, it is a ``ValidationError``. This module is the IO half. It stores
those resources in the control-plane store behind ``M0030_API_RESOURCES``, and
answers the list/filter/sort questions a REST surface asks without ever
reshaping a resource.

Three decisions this module makes, and why
------------------------------------------

**Nested on disk, flat at the query boundary.** The plan's ledger says the API
response shape is nested, and Phase 1 already fixed it nested: a ``RunResource``
*contains* its ``RunRecord``, a ``PlanResource`` its ``ExecutionPlan``, an
``EvidenceReference`` the sealed ``EvidenceEnvelope``. So the authoritative
column is ``resource_json`` — the resource's own ``to_payload()``, verbatim,
which is exactly what :meth:`pydantic.BaseModel.model_validate` accepts back.
Flattening it into columns would create a second, lossy projection of the same
object and would have to be kept in step by hand.

What the other columns *are*, then, is a **query index**: the handful of scalars
a list endpoint filters and sorts on, so ``WHERE status = ?`` never parses JSON.
They are derived from the resource on the way in, never from a caller, and —
this is the part that makes them safe — they are **audited on the way out**.
:meth:`ApiStore.audit_indexes` re-reads every indexed row, re-derives each
column from the stored payload, and refuses on disagreement. An index that has
drifted is therefore a refusal rather than a wrong answer, which is the
difference between a cache and a parallel model.

**Idempotent writes are no-ops, not updates.** Every write is ``INSERT …
ON CONFLICT DO UPDATE … WHERE <payload differs>``, so re-saving the identical
resource leaves the row and its ``revision`` untouched. That is what makes a
retried request safe, and it is checkable: ``revision`` is 1 after one save and
still 1 after any number of repeats.

**The Phase 1 refusals survive persistence.** They are not bypassed by a write
path that trusts its argument. :meth:`ApiStore.put` takes a raw payload dict
and runs it through the same ``model_validate`` Phase 1 uses, and every read
path re-validates what came out of the database. A row whose ``plan_digest``
disagrees with the plan it carries — hand-edited, corrupted, or written by
something that skipped the store — is refused on read, with the same
``api.plan_digest_mismatch`` rule Phase 1 raises. ``tests/unit/test_api_store.py``
writes exactly that row through raw SQL and reads it back.

What this module is not
-----------------------

* **Not a second run store.** ``api_runs`` holds a ``RunResource``; ``runs`` and
  ``m5_runs`` hold the executor's own records. There is no foreign key between
  them on purpose (gap 101): an API projection must survive the control plane
  deleting the record it projects. The ``run_id`` is the same identifier, so
  Phase 3 can join them, but the schema does not make survival conditional.
* **Not the scheduler.** ``api_schedules`` projects a ``Schedule``; the
  ``schedules`` table (M0026) is a *dispatch registration* that additionally
  requires a campaign and tracks window/run-count state. A ``ScheduleResource``
  names no campaign, so folding it in would mean inventing one.
* **Not a service layer.** The plan's Phase 2 also lists planner/policy/
  scheduler/orchestrator/evidence facades. What lands here is the seam they
  need — :meth:`ApiStore.plan_for_run` hands the proof compiler the exact
  ``ExecutionPlan`` whose digest the API displays, and
  :meth:`ApiStore.explain` / :meth:`ApiStore.summarise` run Phase 1's
  report functions over what is stored. The facades themselves are Phase 3's
  gateway.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any, Final, Protocol, Self, TypeVar, cast

from mayhem.domain.api import (
    ApiEnvelope,
    ApprovalResource,
    EvidenceReference,
    ExecutiveSummary,
    ExperimentResource,
    FailureExplanation,
    OutcomeResource,
    PlanResource,
    PlanStepResource,
    PolicyResource,
    RunResource,
    RunTimeline,
    ScheduleResource,
    explain_run,
    summarise,
)
from mayhem.domain.common import utc_now
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.events import Event, EventKind

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Mapping, Sequence

    from mayhem.domain.run_outcome import Outcome
    from mayhem.infra.store import Store

__all__ = [
    "API_RESOURCE_TABLES",
    "ApiStore",
    "IndexedResource",
    "RunFilters",
    "StaleIndexError",
]

#: Every resource type this store persists, in the order the schema declares
#: them. One tuple so a sweep (:meth:`ApiStore.audit_indexes`) and a test that
#: wants to enumerate the tables cannot disagree about the list.
API_RESOURCE_TABLES: Final[tuple[str, ...]] = (
    "api_experiments",
    "api_plans",
    "api_plan_steps",
    "api_runs",
    "api_outcomes",
    "api_approvals",
    "api_policy_decisions",
    "api_schedules",
    "api_evidence_refs",
)

#: The comparison operators a filter may use. Closed for the same reason the
#: column set is: an operator set that accepts anything is an operator set that
#: can express a subquery.
_FILTER_OPERATORS: Final[frozenset[str]] = frozenset({"=", ">=", "<="})

#: Sort keys a list call may name, per table. A whitelist rather than an
#: interpolated identifier: a caller passing ``order_by`` gets a refusal naming
#: the keys that exist, never SQL built from a string nobody validated.
_SORT_KEYS: Final[Mapping[str, tuple[str, ...]]] = {
    "api_experiments": ("name", "spec_digest", "recorded_at"),
    "api_plans": ("plan_digest", "run_id", "policy_id", "recorded_at"),
    "api_plan_steps": ("seq", "step_id", "action_type"),
    "api_runs": (
        "run_id",
        "started_at",
        "ended_at",
        "status",
        "verdict",
        "experiment_name",
        "recorded_at",
    ),
    "api_outcomes": ("run_id", "checks_passed", "checks_failed", "recorded_at"),
    "api_approvals": ("approval_id", "approver", "valid", "recorded_at"),
    "api_policy_decisions": ("decision_digest", "bundle_id", "allowed", "recorded_at"),
    "api_schedules": ("schedule_id", "kind", "timezone_name", "recorded_at"),
    "api_evidence_refs": ("ref_id", "run_id", "complete", "recorded_at"),
}

#: Columns a ``filter`` may name, per table. Same reasoning as ``_SORT_KEYS``:
#: equality filters on indexed scalars only, and the set is closed.
_FILTER_KEYS: Final[Mapping[str, tuple[str, ...]]] = {
    "api_experiments": ("name", "spec_digest", "hypothesis"),
    "api_plans": ("plan_digest", "run_id", "policy_id"),
    "api_plan_steps": ("plan_digest", "step_id", "seq", "action_type", "fault_id"),
    "api_runs": (
        "run_id",
        "plan_digest",
        "status",
        "verdict",
        "experiment_name",
        "started_at",
        "ended_at",
    ),
    "api_outcomes": ("run_id", "plan_digest", "body_hash", "stability_signal"),
    "api_approvals": (
        "approval_id",
        "approval_digest",
        "plan_digest",
        "policy_digest",
        "proof_digest",
        "approver",
        "valid",
    ),
    "api_policy_decisions": (
        "decision_digest",
        "allowed",
        "bundle_id",
        "outcome",
        "policy_digest",
    ),
    "api_schedules": ("schedule_id", "schedule_digest", "kind", "timezone_name"),
    "api_evidence_refs": (
        "ref_id",
        "envelope_digest",
        "run_id",
        "plan_digest",
        "complete",
        "verdict",
        "evidence_status",
    ),
}


class _Storable(Protocol):
    """What a Phase 1 resource must offer to be stored and rebuilt.

    ``to_payload()`` is what goes into the row; ``model_validate`` is what comes
    back out. Both are the Phase 1 contract, so a type that does not have them
    is not a resource and has no business in :data:`API_RESOURCE_TABLES`.
    """

    def to_payload(self) -> dict[str, Any]: ...

    @classmethod
    def model_validate(cls, obj: Any, /) -> Self: ...


#: Bound for the read helpers. The concrete type is inferred from the caller's
#: return annotation, so ``load_experiment`` hands back an ``ExperimentResource``
#: without a cast at every call site. The single cast lives inside the helpers,
#: where the table-to-type registry genuinely is dynamic.
_ResourceT = TypeVar("_ResourceT", bound=_Storable)

#: Column sets, spelled once so a write and the audit sweep cannot drift.
_EXPERIMENT_COLUMNS: Final[str] = (
    "name, spec_digest, hypothesis, signal_count, resource_json, recorded_at"
)
_PLAN_COLUMNS: Final[str] = (
    "plan_digest, run_id, policy_id, config_snapshot_id, topology_snapshot_id, "
    "environment_fingerprint, step_count, resource_json, recorded_at"
)
_PLAN_STEP_COLUMNS: Final[str] = (
    "plan_digest, step_id, seq, action_type, fault_id, logical_target_id, "
    "resolved_target_ids_json, step_json, recorded_at"
)
_RUN_COLUMNS: Final[str] = (
    "run_id, plan_digest, experiment_name, status, verdict, started_at, ended_at, "
    "resource_json, recorded_at"
)
_OUTCOME_COLUMNS: Final[str] = (
    "run_id, plan_digest, checks_passed, checks_failed, body_hash, residual_effect, "
    "stability_signal, resource_json, recorded_at"
)
_APPROVAL_COLUMNS: Final[str] = (
    "approval_id, approval_digest, plan_digest, policy_digest, proof_digest, approver, "
    "valid, reasons_json, resource_json, recorded_at"
)
_POLICY_COLUMNS: Final[str] = (
    "decision_digest, allowed, outcome, bundle_id, bundle_version, policy_digest, "
    "rule_digest, facts_digest, resource_json, recorded_at"
)
_SCHEDULE_COLUMNS: Final[str] = (
    "schedule_id, schedule_digest, kind, timezone_name, horizon, gates_json, "
    "resource_json, recorded_at"
)
_EVIDENCE_COLUMNS: Final[str] = (
    "ref_id, envelope_digest, run_id, plan_digest, complete, verdict, recovery_state, "
    "evidence_status, observation_count, step_report_count, resource_json, recorded_at"
)

#: Resource type per table, so ``_payload_to_resource`` needs no per-table branch
#: at every call site and the audit sweep knows what to validate a row into.
_RESOURCE_FOR_TABLE: Final[Mapping[str, type[_Storable]]] = {
    "api_experiments": ExperimentResource,
    "api_plans": PlanResource,
    "api_plan_steps": PlanStepResource,
    "api_runs": RunResource,
    "api_outcomes": OutcomeResource,
    "api_approvals": ApprovalResource,
    "api_policy_decisions": PolicyResource,
    "api_schedules": ScheduleResource,
    "api_evidence_refs": EvidenceReference,
}


class StaleIndexError(InvariantViolationError):
    """A query-index column disagrees with the resource payload it indexes.

    Raised by :meth:`ApiStore.audit_indexes`. It subclasses
    :class:`~mayhem.domain.errors.InvariantViolationError` so a caller that only
    knows the domain error vocabulary still catches it, and it carries the
    ``rule`` string ``api_store.index_divergence`` like every other refusal in
    the repository.
    """


@dataclass(frozen=True, slots=True)
class IndexedResource:
    """One stored row: the resource, plus the index columns beside it.

    Returned by :meth:`ApiStore.audit_indexes` so a caller can see *both* sides
    of a comparison rather than only the verdict. ``columns`` is the row as read
    and ``expected`` is what the payload says it should be; a non-empty
    ``mismatches`` names the columns that disagree.
    """

    table: str
    key: str
    resource: Any
    columns: Mapping[str, Any]
    expected: Mapping[str, Any]
    mismatches: tuple[str, ...] = ()

    @property
    def consistent(self) -> bool:
        return not self.mismatches


@dataclass(frozen=True, slots=True)
class RunFilters:
    """The filter set ``GET /runs`` accepts. Closed, so a new filter is a change.

    Every field is a column of ``api_runs``; ``None`` means "no constraint on
    this one". A filter the table cannot answer with an index is not offered,
    which is why there is no free-text field here.
    """

    status: str | None = None
    verdict: str | None = None
    experiment_name: str | None = None
    plan_digest: str | None = None
    started_from: str | None = None
    started_to: str | None = None

    def as_predicates(self) -> tuple[tuple[str, str, Any], ...]:
        """The filter set as ``(column, operator, value)`` triples.

        A triple rather than a pair because two of the six constraints are range
        bounds and an operator cannot live in a column name. Both halves stay
        closed: the column must be in :data:`_FILTER_KEYS` and the operator in
        :data:`_FILTER_OPERATORS`, so nothing reaches the SQL that was not
        enumerated here.
        """
        predicates: list[tuple[str, str, Any]] = []
        for column, value in (
            ("status", self.status),
            ("verdict", self.verdict),
            ("experiment_name", self.experiment_name),
            ("plan_digest", self.plan_digest),
        ):
            if value is not None:
                predicates.append((column, "=", value))
        if self.started_from is not None:
            predicates.append(("started_at", ">=", self.started_from))
        if self.started_to is not None:
            predicates.append(("started_at", "<=", self.started_to))
        return tuple(predicates)


# ---------------------------------------------------------------------------
# index derivation — the one place an indexed column is computed
# ---------------------------------------------------------------------------


def _experiment_index(resource: ExperimentResource) -> dict[str, Any]:
    return {
        "name": resource.name,
        "spec_digest": resource.spec_digest,
        "hypothesis": resource.hypothesis,
        "signal_count": len(resource.steady_state_signals),
    }


def _plan_index(resource: PlanResource) -> dict[str, Any]:
    return {
        "plan_digest": resource.plan_digest,
        "run_id": resource.run_id,
        "policy_id": resource.policy_id,
        "config_snapshot_id": resource.config_snapshot_id,
        "topology_snapshot_id": resource.topology_snapshot_id,
        "environment_fingerprint": resource.environment_fingerprint,
        "step_count": len(resource.steps),
    }


def _plan_step_index(plan_digest: str, resource: PlanStepResource) -> dict[str, Any]:
    return {
        "plan_digest": plan_digest,
        "step_id": resource.step_id,
        "seq": resource.seq,
        "action_type": resource.action_type,
        "fault_id": resource.fault_id,
        "logical_target_id": resource.logical_target_id,
        "resolved_target_ids_json": json.dumps(list(resource.resolve_target_ids)),
    }


def _run_index(resource: RunResource) -> dict[str, Any]:
    return {
        "run_id": resource.run_id,
        "plan_digest": resource.plan_digest,
        "experiment_name": resource.experiment_name,
        "status": resource.status,
        "verdict": resource.verdict.value,
        "started_at": resource.record.started_at,
        "ended_at": resource.record.ended_at,
    }


def _outcome_index(resource: OutcomeResource) -> dict[str, Any]:
    outcome: Outcome = resource.to_outcome()
    return {
        "run_id": resource.run_id,
        "plan_digest": resource.plan_digest,
        "checks_passed": outcome.checks_passed,
        "checks_failed": outcome.checks_failed,
        "body_hash": outcome.body_hash,
        "residual_effect": outcome.residual_effect,
        "stability_signal": outcome.stability_signal,
    }


def _approval_index(resource: ApprovalResource) -> dict[str, Any]:
    return {
        "approval_id": resource.approval_id,
        "approval_digest": resource.approval_digest,
        "plan_digest": resource.plan_digest,
        "policy_digest": resource.policy_digest,
        "proof_digest": resource.proof_digest,
        "approver": resource.approver,
        "valid": int(resource.valid),
        "reasons_json": json.dumps(list(resource.reasons)),
    }


def _policy_index(resource: PolicyResource) -> dict[str, Any]:
    return {
        "decision_digest": resource.decision_digest,
        "allowed": int(resource.allowed),
        "outcome": str(resource.decision.outcome),
        "bundle_id": resource.bundle_id,
        "bundle_version": resource.bundle_version,
        "policy_digest": resource.policy_digest,
        "rule_digest": resource.rule_digest,
        "facts_digest": resource.facts_digest,
    }


def _schedule_index(resource: ScheduleResource) -> dict[str, Any]:
    return {
        "schedule_id": resource.schedule_id,
        "schedule_digest": resource.schedule_digest,
        "kind": resource.kind,
        "timezone_name": resource.timezone_name,
        "horizon": resource.horizon,
        "gates_json": json.dumps(list(resource.gates)),
    }


def _evidence_index(resource: EvidenceReference) -> dict[str, Any]:
    envelope = resource.to_envelope()
    return {
        "ref_id": resource.ref_id,
        "envelope_digest": resource.envelope_digest,
        "run_id": resource.run_id,
        "plan_digest": resource.plan_digest,
        "complete": int(resource.complete),
        "verdict": str(envelope.verdict),
        "recovery_state": str(envelope.recovery_state),
        "evidence_status": str(envelope.evidence_status),
        "observation_count": len(envelope.observations),
        "step_report_count": len(envelope.step_reports),
    }


#: Column -> how to re-derive it from the reconstructed resource. The audit
#: sweep and the write path both go through this mapping, which is what makes
#: "audited" mean the write and the check read the same definition.
_INDEX_READERS: Final[Mapping[str, Callable[..., dict[str, Any]]]] = {
    "api_experiments": _experiment_index,
    "api_plans": _plan_index,
    "api_plan_steps": _plan_step_index,
    "api_runs": _run_index,
    "api_outcomes": _outcome_index,
    "api_approvals": _approval_index,
    "api_policy_decisions": _policy_index,
    "api_schedules": _schedule_index,
    "api_evidence_refs": _evidence_index,
}

#: The column holding the resource's wire form. ``api_plan_steps`` is the one
#: table that calls it something else, because its payload is a *step* nested
#: inside a plan rather than a resource in its own right -- the name
#: ``step_json`` is what tells a reader of the schema which of the two it is.
_PAYLOAD_COLUMN: Final[Mapping[str, str]] = {
    "api_plan_steps": "step_json",
    **{table: "resource_json" for table in API_RESOURCE_TABLES if table != "api_plan_steps"},
}

#: The primary key of each table, for the upsert conflict target.
_KEY_COLUMN: Final[Mapping[str, str]] = {
    "api_experiments": "name",
    "api_plans": "plan_digest",
    "api_plan_steps": "step_id",
    "api_runs": "run_id",
    "api_outcomes": "run_id",
    "api_approvals": "approval_id",
    "api_policy_decisions": "decision_digest",
    "api_schedules": "schedule_id",
    "api_evidence_refs": "ref_id",
}

#: ``api_plan_steps`` is keyed by (plan_digest, step_id) and its digest is the
#: plan's, not the step's, so it needs the caller to supply one extra value and
#: it is excluded from the two-argument "write a resource" path.
_COMPOSITE_KEY_TABLES: Final[frozenset[str]] = frozenset({"api_plan_steps"})


def _require_sorted_key(table: str, order_by: str) -> str:
    allowed = _SORT_KEYS.get(table, ())
    if order_by not in allowed:
        msg = (
            f"cannot order {table} by {order_by!r}: sortable keys are "
            f"{list(allowed)}, and a sort key nobody validated is not a sort "
            "order, it is SQL"
        )
        raise InvariantViolationError("api_store.unknown_sort_key", msg)
    return order_by


def _require_filter(table: str, column: str, operator: str) -> None:
    """One column and one operator, both enumerated, or a refusal naming them."""
    allowed = _FILTER_KEYS.get(table, ())
    if column not in allowed:
        msg = (
            f"cannot filter {table} on {column!r}: filterable columns are {list(allowed)}. "
            "A filter the index cannot answer is a full scan pretending to be a query"
        )
        raise InvariantViolationError("api_store.unknown_filter_key", msg)
    if operator not in _FILTER_OPERATORS:
        msg = (
            f"cannot filter {table} with operator {operator!r}: the operators are "
            f"{sorted(_FILTER_OPERATORS)}. An operator set that accepts anything is an "
            "operator set that can express a subquery"
        )
        raise InvariantViolationError("api_store.unknown_filter_operator", msg)


class ApiStore:
    """Read/write access to the Phase 1 resource vocabulary, over one store.

    Constructed over an already-migrated :class:`~mayhem.infra.store.Store`, so
    the single-writer discipline of ADR-0007 is inherited rather than
    reimplemented: every method here goes through ``Store.write`` (one
    transaction per call) or ``Store.query``, and this module never opens a
    connection of its own.
    """

    def __init__(self, store: Store) -> None:
        self._store = store

    @property
    def store(self) -> Store:
        """The underlying store, for callers that need a non-resource write."""
        return self._store

    # -- generic write / read ------------------------------------------------

    def _put(self, table: str, index: Mapping[str, Any], resource: _Storable) -> int:
        """Insert or update one row; return the ``revision`` it now holds.

        The ``WHERE`` on the conflict arm is the idempotency mechanism: a write
        whose payload already matches the stored one is not an update, so the
        row and its revision are untouched. A retried request therefore cannot
        look like a second event.
        """
        key = _KEY_COLUMN[table]
        columns = [*index, "resource_json", "recorded_at"]
        values = [*index.values(), _payload(resource), utc_now().isoformat()]
        placeholders = ",".join("?" for _ in columns)
        updates = ",".join(f"{col}=excluded.{col}" for col in columns if col != key)
        sql = (
            f"INSERT INTO {table} ({','.join(columns)}, revision) "
            f"VALUES ({placeholders}, 1) "
            f"ON CONFLICT({key}) DO UPDATE SET {updates}, revision={table}.revision + 1 "
            f"WHERE {table}.resource_json <> excluded.resource_json"
        )
        with self._store.write() as conn:
            conn.execute(sql, tuple(values))
            row = conn.execute(
                f"SELECT revision FROM {table} WHERE {key} = ?", (index[key],)
            ).fetchone()
        return int(row["revision"]) if row else 1

    def _load(self, table: str, key: Any) -> _ResourceT | None:
        rows = self._store.query(
            f"SELECT {_PAYLOAD_COLUMN[table]} FROM {table} WHERE {_KEY_COLUMN[table]} = ?",
            (key,),
        )
        if not rows:
            return None
        return cast(
            "_ResourceT", _resource_from_payload(table, str(rows[0][_PAYLOAD_COLUMN[table]]))
        )

    def _list(
        self,
        table: str,
        *,
        filters: Iterable[tuple[str, str, Any]] | None = None,
        order_by: str = "",
        descending: bool = False,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[_ResourceT]:
        """Filtered, sorted, paged rows, each re-validated on the way out."""
        clauses: list[str] = []
        params: list[Any] = []
        for column, operator, value in filters or ():
            if value is None:
                continue
            _require_filter(table, column, operator)
            clauses.append(f"{column} {operator} ?")
            params.append(value)
        sql = f"SELECT {_PAYLOAD_COLUMN[table]} AS resource_json FROM {table}"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        # The key column is appended as a tiebreak on every ordering, because a
        # total order is what makes a paged read reproducible: without it, two
        # rows that tie on the sort key can come back in either order, and a
        # client walking pages with a limit can see one of them twice. The same
        # reason `infra.schedule_store` sorts its listing by id.
        key = _KEY_COLUMN[table]
        if order_by:
            column = _require_sorted_key(table, order_by)
            direction = "DESC" if descending else "ASC"
            sql += f" ORDER BY {column} {direction}, {key} ASC"
        else:
            sql += f" ORDER BY {key} ASC"
        if limit is not None:
            if limit < 1:
                msg = f"limit must be at least 1, got {limit}: a page of nothing is not a page"
                raise InvariantViolationError("api_store.bad_limit", msg)
            sql += " LIMIT ?"
            params.append(limit)
        if offset:
            if offset < 0:
                msg = f"offset must not be negative, got {offset}"
                raise InvariantViolationError("api_store.bad_offset", msg)
            sql += " OFFSET ?"
            params.append(offset)
        rows = self._store.query(sql, tuple(params))
        return [
            cast("_ResourceT", _resource_from_payload(table, str(row["resource_json"])))
            for row in rows
        ]

    # -- experiments ---------------------------------------------------------

    def save_experiment(self, resource: ExperimentResource) -> int:
        return self._put("api_experiments", _experiment_index(resource), resource)

    def put_experiment(self, payload: Mapping[str, Any]) -> ExperimentResource:
        """Validate a wire payload, then store it. Refusal happens before the write."""
        resource = ExperimentResource.model_validate(dict(payload))
        self.save_experiment(resource)
        return resource

    def load_experiment(self, name: str) -> ExperimentResource | None:
        return self._load("api_experiments", name)

    def list_experiments(
        self,
        *,
        name: str | None = None,
        spec_digest: str | None = None,
        order_by: str = "name",
        descending: bool = False,
        limit: int | None = None,
        offset: int = 0,
    ) -> tuple[ExperimentResource, ...]:
        rows: list[ExperimentResource] = self._list(
            "api_experiments",
            filters=(("name", "=", name), ("spec_digest", "=", spec_digest)),
            order_by=order_by,
            descending=descending,
            limit=limit,
            offset=offset,
        )
        return tuple(rows)

    # -- plans and plan steps ----------------------------------------------

    def save_plan(self, resource: PlanResource) -> int:
        """Store a plan and, in the same transaction, its step projections.

        One transaction deliberately: a plan whose steps were half-written
        would render a plan the executor never ran, and the step list is the
        part a reader scrolls. Steps are deleted-then-rewritten rather than
        merged, because a plan is frozen — its digest covers its step list, so
        the step rows for a digest can only ever be the same rows.
        """
        index = _plan_index(resource)
        revision = self._put("api_plans", index, resource)
        with self._store.write() as conn:
            conn.execute(
                "DELETE FROM api_plan_steps WHERE plan_digest = ?", (resource.plan_digest,)
            )
            now = utc_now().isoformat()
            for step in resource.steps:
                step_index = _plan_step_index(resource.plan_digest, step)
                conn.execute(
                    f"INSERT INTO api_plan_steps ({_PLAN_STEP_COLUMNS}) VALUES (?,?,?,?,?,?,?,?,?)",
                    (
                        step_index["plan_digest"],
                        step_index["step_id"],
                        step_index["seq"],
                        step_index["action_type"],
                        step_index["fault_id"],
                        step_index["logical_target_id"],
                        step_index["resolved_target_ids_json"],
                        _payload(step),
                        now,
                    ),
                )
        return revision

    def put_plan(self, payload: Mapping[str, Any]) -> PlanResource:
        resource = PlanResource.model_validate(dict(payload))
        self.save_plan(resource)
        return resource

    def load_plan(self, plan_digest: str) -> PlanResource | None:
        return self._load("api_plans", plan_digest)

    def list_plans(
        self,
        *,
        run_id: str | None = None,
        policy_id: str | None = None,
        order_by: str = "plan_digest",
        descending: bool = False,
        limit: int | None = None,
        offset: int = 0,
    ) -> tuple[PlanResource, ...]:
        rows: list[PlanResource] = self._list(
            "api_plans",
            filters=(("run_id", "=", run_id), ("policy_id", "=", policy_id)),
            order_by=order_by,
            descending=descending,
            limit=limit,
            offset=offset,
        )
        return tuple(rows)

    def plan_for_run(self, run_id: str) -> PlanResource | None:
        """The plan a run executed, as the resource the API displays it.

        This is the seam ``controller.safety_proof`` compiles over: the
        ``ExecutionPlan`` handed back by :meth:`PlanResource.to_plan` hashes to
        ``resource.plan_digest``, which is the same value
        :func:`~mayhem.controller.safety_proof.canonical_plan_digest` computes
        and the same value a ``RunResource`` for the same run carries. The
        compiler can therefore be handed a loaded plan without a caller having to
        re-derive which plan it is, and a proof can be compared to a dashboard
        row by digest alone.
        """
        rows: list[PlanResource] = self._list(
            "api_plans", filters=(("run_id", "=", run_id),), order_by="plan_digest"
        )
        return rows[0] if rows else None

    def load_plan_step(self, plan_digest: str, step_id: str) -> PlanStepResource | None:
        rows = self._store.query(
            "SELECT step_json FROM api_plan_steps WHERE plan_digest = ? AND step_id = ?",
            (plan_digest, step_id),
        )
        if not rows:
            return None
        return cast(
            "PlanStepResource",
            _resource_from_payload("api_plan_steps", str(rows[0]["step_json"])),
        )

    def list_plan_steps(
        self,
        plan_digest: str,
        *,
        action_type: str | None = None,
        fault_id: str | None = None,
        order_by: str = "seq",
        descending: bool = False,
    ) -> tuple[PlanStepResource, ...]:
        rows: list[PlanStepResource] = self._list(
            "api_plan_steps",
            filters=(
                ("plan_digest", "=", plan_digest),
                ("action_type", "=", action_type),
                ("fault_id", "=", fault_id),
            ),
            order_by=order_by,
            descending=descending,
        )
        return tuple(rows)

    # -- runs and outcomes ---------------------------------------------------

    def save_run(self, resource: RunResource) -> int:
        return self._put("api_runs", _run_index(resource), resource)

    def put_run(self, payload: Mapping[str, Any]) -> RunResource:
        resource = RunResource.model_validate(dict(payload))
        self.save_run(resource)
        return resource

    def load_run(self, run_id: str) -> RunResource | None:
        return self._load("api_runs", run_id)

    def list_runs(
        self,
        filters: RunFilters | None = None,
        *,
        order_by: str = "started_at",
        descending: bool = True,
        limit: int | None = None,
        offset: int = 0,
    ) -> tuple[RunResource, ...]:
        chosen = filters or RunFilters()
        rows: list[RunResource] = self._list(
            "api_runs",
            filters=chosen.as_predicates(),
            order_by=order_by,
            descending=descending,
            limit=limit,
            offset=offset,
        )
        return tuple(rows)

    def save_outcome(self, resource: OutcomeResource) -> int:
        return self._put("api_outcomes", _outcome_index(resource), resource)

    def put_outcome(self, payload: Mapping[str, Any]) -> OutcomeResource:
        resource = OutcomeResource.model_validate(dict(payload))
        self.save_outcome(resource)
        return resource

    def load_outcome(self, run_id: str) -> OutcomeResource | None:
        return self._load("api_outcomes", run_id)

    def list_outcomes(
        self,
        *,
        plan_digest: str | None = None,
        order_by: str = "run_id",
        descending: bool = False,
    ) -> tuple[OutcomeResource, ...]:
        rows: list[OutcomeResource] = self._list(
            "api_outcomes",
            filters=(("plan_digest", "=", plan_digest),),
            order_by=order_by,
            descending=descending,
        )
        return tuple(rows)

    # -- approvals, policies, schedules, evidence ---------------------------

    def save_approval(self, resource: ApprovalResource) -> int:
        return self._put("api_approvals", _approval_index(resource), resource)

    def put_approval(self, payload: Mapping[str, Any]) -> ApprovalResource:
        resource = ApprovalResource.model_validate(dict(payload))
        self.save_approval(resource)
        return resource

    def load_approval(self, approval_id: str) -> ApprovalResource | None:
        return self._load("api_approvals", approval_id)

    def list_approvals(
        self,
        *,
        plan_digest: str | None = None,
        approver: str | None = None,
        valid: bool | None = None,
        order_by: str = "approval_id",
        descending: bool = False,
    ) -> tuple[ApprovalResource, ...]:
        rows: list[ApprovalResource] = self._list(
            "api_approvals",
            filters=(
                ("plan_digest", "=", plan_digest),
                ("approver", "=", approver),
                ("valid", "=", None if valid is None else int(valid)),
            ),
            order_by=order_by,
            descending=descending,
        )
        return tuple(rows)

    def save_policy_decision(self, resource: PolicyResource) -> int:
        return self._put("api_policy_decisions", _policy_index(resource), resource)

    def put_policy_decision(self, payload: Mapping[str, Any]) -> PolicyResource:
        resource = PolicyResource.model_validate(dict(payload))
        self.save_policy_decision(resource)
        return resource

    def load_policy_decision(self, decision_digest: str) -> PolicyResource | None:
        return self._load("api_policy_decisions", decision_digest)

    def list_policy_decisions(
        self,
        *,
        allowed: bool | None = None,
        bundle_id: str | None = None,
        order_by: str = "decision_digest",
        descending: bool = False,
    ) -> tuple[PolicyResource, ...]:
        rows: list[PolicyResource] = self._list(
            "api_policy_decisions",
            filters=(
                ("allowed", "=", None if allowed is None else int(allowed)),
                ("bundle_id", "=", bundle_id),
            ),
            order_by=order_by,
            descending=descending,
        )
        return tuple(rows)

    def save_schedule(self, resource: ScheduleResource) -> int:
        return self._put("api_schedules", _schedule_index(resource), resource)

    def put_schedule(self, payload: Mapping[str, Any]) -> ScheduleResource:
        resource = ScheduleResource.model_validate(dict(payload))
        self.save_schedule(resource)
        return resource

    def load_schedule(self, schedule_id: str) -> ScheduleResource | None:
        return self._load("api_schedules", schedule_id)

    def list_schedules(
        self,
        *,
        kind: str | None = None,
        timezone_name: str | None = None,
        order_by: str = "schedule_id",
        descending: bool = False,
    ) -> tuple[ScheduleResource, ...]:
        rows: list[ScheduleResource] = self._list(
            "api_schedules",
            filters=(("kind", "=", kind), ("timezone_name", "=", timezone_name)),
            order_by=order_by,
            descending=descending,
        )
        return tuple(rows)

    def save_evidence(self, resource: EvidenceReference) -> int:
        return self._put("api_evidence_refs", _evidence_index(resource), resource)

    def put_evidence(self, payload: Mapping[str, Any]) -> EvidenceReference:
        resource = EvidenceReference.model_validate(dict(payload))
        self.save_evidence(resource)
        return resource

    def load_evidence(self, ref_id: str) -> EvidenceReference | None:
        return self._load("api_evidence_refs", ref_id)

    def list_evidence(
        self,
        *,
        run_id: str | None = None,
        plan_digest: str | None = None,
        complete: bool | None = None,
        order_by: str = "ref_id",
        descending: bool = False,
        limit: int | None = None,
        offset: int = 0,
    ) -> tuple[EvidenceReference, ...]:
        rows: list[EvidenceReference] = self._list(
            "api_evidence_refs",
            filters=(
                ("run_id", "=", run_id),
                ("plan_digest", "=", plan_digest),
                ("complete", "=", None if complete is None else int(complete)),
            ),
            order_by=order_by,
            descending=descending,
            limit=limit,
            offset=offset,
        )
        return tuple(rows)

    def evidence_for_run(self, run_id: str) -> EvidenceReference | None:
        """The envelope sealed for a run, or ``None`` if no envelope is recorded.

        Named separately from :meth:`list_evidence` because the two answers mean
        different things to a caller: an empty filtered list is "none matched
        your filter", and ``None`` here is specifically "this run has no
        evidence", which is the fact ``domain.api.summarise`` reports as an
        unlinked run.
        """
        found = self.list_evidence(run_id=run_id, limit=1)
        return found[0] if found else None

    # -- derived Phase 1 views over what is stored --------------------------

    def explain(self, run_id: str) -> FailureExplanation:
        """Phase 1's failure report for a run, read out of the store.

        Assembles exactly the three records :func:`~mayhem.domain.api.explain_run`
        takes and hands them over. It deliberately does not decide anything: the
        graded verdict is read from the sealed envelope's payload, and a section
        the stored observations cannot support is withheld with a named reason
        by the domain function, not by this one.
        """
        run = self.load_run(run_id)
        if run is None:
            msg = (
                f"no API run resource is recorded for run {run_id!r}, so there is "
                "nothing to explain"
            )
            raise InvariantViolationError("api_store.run_not_stored", msg)
        evidence = self.evidence_for_run(run_id)
        if evidence is None:
            msg = (
                f"no evidence reference is recorded for run {run_id!r}: a failure "
                "explanation assembled with no envelope would have nothing to cite"
            )
            raise InvariantViolationError("api_store.evidence_not_stored", msg)
        return explain_run(run=run, evidence=evidence, outcome=self.load_outcome(run_id))

    def summarise(
        self,
        run_ids: Sequence[str],
        *,
        evidence: Mapping[str, EvidenceReference] | None = None,
    ) -> ExecutiveSummary:
        """Phase 1's executive summary over stored runs.

        A run with no recorded envelope contributes to no number; the domain
        function names it in ``unlinked_runs`` with the reason, which is the
        property that makes "a dashboard number always links to evidence"
        checkable rather than aspirational.
        """
        runs = [run for run in (self.load_run(run_id) for run_id in run_ids) if run is not None]
        linked = dict(evidence or {})
        if not linked:
            linked = {
                resource.run_id: resource
                for resource in (self.evidence_for_run(run_id) for run_id in run_ids)
                if resource is not None
            }
        return summarise(runs=runs, evidence=linked)

    def timeline(self, run_id: str) -> RunTimeline:
        """The Phase 1 timeline for a run, rebuilt from the stored ``events``.

        Reads the journal the executor already writes and hands the events to
        :meth:`~mayhem.domain.api.RunTimeline.of`, so the points are derived
        here and never stored. Nothing in this module writes a timeline row: a
        table of timeline points would be a second account of the same events,
        and gap 32 is closed by having no such table at all.
        """
        run = self.load_run(run_id)
        if run is None:
            msg = f"no API run resource is recorded for run {run_id!r}, so it has no timeline"
            raise InvariantViolationError("api_store.run_not_stored", msg)
        events: list[Event] = []
        for row in self._store.query(
            "SELECT ts, kind, payload_json FROM events WHERE run_id = ? ORDER BY id", (run_id,)
        ):
            detail = _loads(str(row["payload_json"]))
            events.append(
                Event(
                    kind=_event_kind(str(row["kind"])),
                    run_id=run_id,
                    detail=detail if isinstance(detail, dict) else {},
                    created_at_epoch_s=_epoch_of(str(row["ts"])),
                )
            )
        return RunTimeline.of(events, run_id=run_id, plan_digest=run.plan_digest)

    def envelope_for_run(self, run_id: str) -> ApiEnvelope:
        """A Phase 1 :class:`~mayhem.domain.api.ApiEnvelope` over one run.

        The last piece the surface needs from the store: the ``data`` is the
        resource's own ``to_dict()`` — the nested rendering Phase 1 fixed — and
        ``evidence_refs`` names the envelope, so even the envelope shape carries
        the provenance link Phase 4's acceptance asks for.
        """
        run = self.load_run(run_id)
        if run is None:
            msg = f"no API run resource is recorded for run {run_id!r}"
            raise InvariantViolationError("api_store.run_not_stored", msg)
        evidence = self.evidence_for_run(run_id)
        return ApiEnvelope.ok(
            {"run": run.to_dict()},
            evidence_refs=(evidence.ref_id,) if evidence is not None else (),
            meta={"resource": "api_runs", "run_id": run_id},
        )

    # -- the index audit -----------------------------------------------------

    def audit_indexes(self, *, table: str | None = None) -> tuple[IndexedResource, ...]:
        """Re-derive every indexed column from its stored payload.

        The audit that makes the denormalised columns a cache rather than a
        parallel model. A column that disagrees with the payload it indexes is
        reported as an :class:`IndexedResource` with a non-empty ``mismatches``
        tuple; with ``strict=True`` (the default) the first disagreement is
        raised as :class:`StaleIndexError` instead, because an index that has
        drifted is not something a caller should be handed a list around.
        """
        return self._audit(table=table, strict=True)

    def audit_indexes_lenient(self, *, table: str | None = None) -> tuple[IndexedResource, ...]:
        """The same sweep, reporting disagreements instead of raising."""
        return self._audit(table=table, strict=False)

    def _audit(self, *, table: str | None, strict: bool) -> tuple[IndexedResource, ...]:
        tables = (table,) if table is not None else API_RESOURCE_TABLES
        unknown = sorted(set(tables) - set(_INDEX_READERS))
        if unknown:
            msg = (
                f"cannot audit {unknown}: the resource tables are {list(API_RESOURCE_TABLES)}. "
                "An audited table nobody enumerated is a table nobody checked"
            )
            raise InvariantViolationError("api_store.unknown_table", msg)
        findings: list[IndexedResource] = []
        for name in tables:
            reader = _INDEX_READERS[name]
            for row in self._store.query(f"SELECT * FROM {name}"):
                resource = _resource_from_payload(name, str(row[_PAYLOAD_COLUMN[name]]))
                if name in _COMPOSITE_KEY_TABLES:
                    expected = reader(str(row["plan_digest"]), resource)
                else:
                    expected = reader(resource)
                mismatches = tuple(
                    sorted(
                        column
                        for column, value in expected.items()
                        if str(row[column]) != str(value)
                    )
                )
                key = str(row[_KEY_COLUMN[name]])
                finding = IndexedResource(
                    table=name,
                    key=key,
                    resource=resource,
                    columns={column: row[column] for column in expected},
                    expected=dict(expected),
                    mismatches=mismatches,
                )
                findings.append(finding)
                if mismatches and strict:
                    msg = (
                        f"{name} row {key!r} indexes {mismatches} as "
                        f"{[finding.columns[column] for column in mismatches]} while its "
                        f"resource says {[finding.expected[column] for column in mismatches]}: "
                        "a query index that has drifted from the resource it indexes answers "
                        "a different question from the one the API asked"
                    )
                    raise StaleIndexError("api_store.index_divergence", msg)
        return tuple(findings)


# ---------------------------------------------------------------------------
# payload helpers
# ---------------------------------------------------------------------------


def _payload(resource: Any) -> str:
    """The reconstructible wire form, as compact JSON.

    ``to_payload()`` and not ``to_dict()``: the latter adds the denormalised
    read fields a ``GET`` renders, which are *not* accepted back by
    ``model_validate``. Storing the rendering would make the row unloadable.
    """
    return json.dumps(resource.to_payload(), sort_keys=True, separators=(",", ":"))


def _resource_from_payload(table: str, raw: str) -> _Storable:
    """Rebuild a resource from a stored payload, re-running Phase 1's validators.

    The re-validation is the point. Phase 1's guarantee is that a resource
    cannot disagree with the domain object it contains; if the load path trusted
    the stored bytes, that guarantee would hold at write time and evaporate the
    moment a row was edited by anything other than this module. So every read
    goes through ``model_validate`` and a row whose digest no longer matches its
    payload is refused with the same rule Phase 1 raises.
    """
    resource_type = _RESOURCE_FOR_TABLE.get(table)
    if resource_type is None:
        msg = f"no API resource type is registered for table {table!r}"
        raise InvariantViolationError("api_store.unknown_table", msg)
    return resource_type.model_validate(_loads(raw))


def _loads(raw: str) -> Any:
    try:
        return json.loads(raw)
    except (TypeError, ValueError) as exc:
        msg = f"stored API payload is not JSON ({exc})"
        raise InvariantViolationError("api_store.unreadable_payload", msg) from exc


def _event_kind(name: str) -> EventKind:
    try:
        return EventKind(name)
    except ValueError as exc:
        msg = (
            f"the stored journal names event kind {name!r}, which this build does not "
            "know: an event a timeline cannot place is an event a timeline would drop"
        )
        raise InvariantViolationError("api_store.unknown_event_kind", msg) from exc


def _epoch_of(stamp: str) -> float:
    """A journal row's ISO-8601 ``ts`` as the epoch seconds ``Event`` carries.

    The executor writes ``utc_now().isoformat()`` into ``events.ts`` and Phase 1
    orders a timeline by ``created_at_epoch_s``, so the conversion belongs here
    rather than in the domain — the domain has no clock and no storage.
    """
    try:
        return datetime.fromisoformat(stamp).timestamp()
    except ValueError as exc:
        msg = f"stored journal timestamp {stamp!r} is not ISO-8601: {exc}"
        raise InvariantViolationError("api_store.unreadable_timestamp", msg) from exc
