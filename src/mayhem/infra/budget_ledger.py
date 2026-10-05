"""The one persisted half of the damage-budget ledger — ``infra`` because it is IO.

The ledger's vocabulary (the ``HierarchicalBudgetLedger`` protocol, the entry
type, and the commit path in :mod:`mayhem.domain.policy_gate`) is pure and lives
in the domain with the rest of the policy engine. This class is the part that
touches a database: it reads and writes ``observations`` through ``Store``, whose
writes pass that store's evidence boundary. Moving it here is what lets the whole
engine sit below ``infra`` instead of beside it — the store that persists policy
bundles then imports domain rather than reaching upward into a controller.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import TYPE_CHECKING

from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.policy import BudgetLedgerEntry, BudgetScope
from mayhem.domain.policy_gate import KIND_BUDGET_CHARGE

if TYPE_CHECKING:
    from mayhem.infra.store import Store


class ObservationBudgetLedger:
    """The hierarchical damage ledger, persisted through ``Store``'s observations.

    **Why ``observations`` and not a table of its own.** Three reasons, and the
    first two are the ones that decide it:

    * The table already exists, already carries ``kind`` / ``run_id`` / ``source``
      / ``data_json`` / ``timestamp``, and is already indexed on the first two.
      A charge is an append-only record of an event attributed to a run, which is
      what that table *is*.
    * Its writes pass through
      :meth:`~mayhem.infra.store.Store.save_observation`'s evidence boundary
      before the transaction opens, so a budget charge is graded by the same rule
      as the evidence that describes it. A dedicated table written directly would
      be the one evidence-adjacent write in the repository with no such gate.
    * Adding a migration is not this work item's to do. ``infra/migrations.py`` is
      another module's, its head is 37, and the chain is required to be strictly
      increasing — so a new table would mean claiming an id in a file this change
      does not own. Recorded as an open question in the plan rather than taken
      silently.

    What this costs is written down rather than glossed: ``observations`` has no
    uniqueness constraint on its body, so a *repeated* commit double-charges. The
    caller owns calling this once per admitted run. The alternative — an
    idempotency key — needs a unique index, which needs a migration.

    ``charged_at`` goes in ``data`` rather than relying on the row's ``timestamp``
    because the row's timestamp is the *store's* clock and the charge's is the
    gate's. Both are recorded; the gate's is authoritative for reproduction,
    because it is the clock the decision was reached against.
    """

    def __init__(self, store: Store) -> None:
        self._store = store

    def append(self, entry: BudgetLedgerEntry) -> None:
        self._store.save_observation(
            KIND_BUDGET_CHARGE,
            run_id=entry.run_id,
            source=entry.scope.value,
            data={
                "scope": entry.scope.value,
                "budget_key": entry.key,
                "amount_s": entry.amount_s,
                "charged_at": entry.charged_at.isoformat(),
            },
        )

    def entries(self) -> tuple[BudgetLedgerEntry, ...]:
        rows = self._store.query(
            "SELECT run_id, timestamp, data_json FROM observations WHERE kind = ? ORDER BY id",
            (KIND_BUDGET_CHARGE,),
        )
        return tuple(
            _ledger_entry(row["run_id"], row["timestamp"], row["data_json"]) for row in rows
        )


def _ledger_entry(run_id: str, timestamp: str, data_json: str) -> BudgetLedgerEntry:
    """Rebuild one ledger entry from an ``observations`` row, or refuse.

    A row that cannot be read is **not** skipped, and this is the read side's
    version of the rule the write side is written against. Skipping it would
    understate the spend on the branch it belonged to and hand the next run more
    headroom than the ledger actually has — the exact failure the whole commit
    path exists to prevent, arriving through the read instead of the write. So an
    unreadable row refuses, naming the row that could not be read.

    The row's own ``timestamp`` is the fallback for ``charged_at`` so a row
    written before ``charged_at`` was in the payload still reads, rather than
    becoming a permanently unreadable row nobody can delete (the table has no
    delete path either).
    """
    try:
        data = json.loads(data_json) if data_json else {}
        return BudgetLedgerEntry(
            scope=BudgetScope(data["scope"]),
            key=str(data["budget_key"]),
            amount_s=float(data["amount_s"]),
            run_id=run_id,
            charged_at=datetime.fromisoformat(str(data.get("charged_at") or timestamp)),
        )
    except (KeyError, TypeError, ValueError, InvariantViolationError) as exc:
        msg = (
            f"damage budget ledger row for run {run_id or '<none>'} at {timestamp} "
            f"is unreadable and was not skipped: {exc}"
        )
        raise InvariantViolationError("budget.ledger_entry_invalid", msg) from exc
