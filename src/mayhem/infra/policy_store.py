"""Persistence for authored policy bundles — plan 07 Phase 3's storage half.

Plan 07 Phases 1, 2 and 4 built the policy vocabulary, put it inside the real
gate, and sealed what the gate decided. Between them sat the hole Phase 4
recorded and this module closes: **nothing authored, stored, or selected a
bundle.** :class:`~mayhem.controller.policy_authoring.PolicyCatalog` was an
in-memory registry with no IO, so a policy that could be written down could not
be kept, and every run still reached the gate with the older ``config.py``
policy block alone deciding.

What is persisted, and what this store refuses to do
-----------------------------------------------------

* **One row per ``(bundle_id, version)``, written once.** The catalog already
  refuses to republish a version with different content; this table makes the
  same promise structural, so a second spelling of "the policy" cannot exist even
  for a caller that skipped the catalog.
* **The canonical document beside its digest.** ``document`` is the bundle as
  published; ``content_digest`` is what an approval or an evidence record names.
  A reader re-derives the digest from the document and compares, so a row whose
  digest and content disagree is detectable rather than authoritative.
* **Retirement, not deletion.** :meth:`PolicyStore.retire` writes an instant.
  There is no delete method and no ``DELETE`` path here, because an approval or a
  replay from six weeks ago still names that version.
* **No verdict column.** A stored "this policy allowed X" would be a second home
  for a decision the gate re-derives on every run.

Everything this module enforces beyond the row shape is enforced by the
catalog, so the storage layer holds no policy rules of its own — a rule that
reads differently here than in :mod:`mayhem.controller.policy_authoring` is a
bug in one of them, not a policy variant.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from mayhem.controller.policy_authoring import (
    PolicyAuthoringError,
    PolicyCatalog,
    ResolvedPolicy,
    bundle_from_mapping,
)
from mayhem.domain.common import utc_now

if TYPE_CHECKING:
    from collections.abc import Mapping
    from datetime import datetime

    from mayhem.domain.experiments import ExecutionPlan
    from mayhem.domain.policy import PolicyBundle
    from mayhem.infra.store import Store


@dataclass(frozen=True, slots=True)
class PublishedBundle:
    """One stored row, read. What the ``mayhem policy list`` table renders.

    Attributes:
        bundle_id: The bundle's name.
        version: Its version number.
        content_digest: The digest an approval or evidence record would name.
        published_at: When it was published, as stored.
        published_by: Who published it, as declared. Nothing authenticates it.
        retired_at: When it was retired, or ``None`` while it is live.
    """

    bundle_id: str
    version: int
    content_digest: str
    published_at: str
    published_by: str
    retired_at: str | None


class PolicyStore:
    """The catalog, persisted. Read and write, one transaction per write."""

    def __init__(self, store: Store) -> None:
        self._store = store

    # -- write ----------------------------------------------------------------

    def publish(
        self,
        document: Mapping[str, Any],
        *,
        now: datetime | None = None,
        published_by: str = "",
    ) -> ResolvedPolicy:
        """Author ``document`` into a bundle, publish it, and return what resolved.

        The catalog is rebuilt from the stored rows first, so immutability and
        version ordering are decided against everything ever published rather
        than against whatever this process happens to be holding.
        """
        moment = now or utc_now()
        catalog = self.catalog()
        bundle = bundle_from_mapping(document, created_at=_adopt_created_at(document, catalog))
        already = (bundle.bundle_id, bundle.version) in catalog
        # The catalog decides: it refuses a retired version and a rewritten one,
        # and returns itself for identical content. Only a genuinely new version
        # reaches the INSERT — a replayed publish must not write a second row for
        # a pair the unique index already holds.
        catalog = catalog.publish(bundle)
        if already:
            return catalog.resolve(bundle.bundle_id, bundle.version, now=moment)
        with self._store.write() as conn:
            conn.execute(
                """
                INSERT INTO policy_bundles (
                    bundle_id, version, content_digest, document,
                    published_at, published_by, retired_at
                ) VALUES (?, ?, ?, ?, ?, ?, NULL)
                """,
                (
                    bundle.bundle_id,
                    bundle.version,
                    bundle.content_digest,
                    _canonical(bundle),
                    moment.isoformat(),
                    published_by,
                ),
            )
        return catalog.resolve(bundle.bundle_id, bundle.version, now=moment)

    def retire(self, bundle_id: str, version: int, *, now: datetime | None = None) -> None:
        """Tombstone a published version. See the module docstring for why.

        Raises:
            PolicyAuthoringError: If the version is not published, or is already
                retired. Both are refusals rather than silent no-ops: a
                tombstone for something nobody published asserts a history that
                did not happen.
        """
        moment = now or utc_now()
        catalog = self.catalog().retire(bundle_id, version)
        with self._store.write() as conn:
            updated = conn.execute(
                "UPDATE policy_bundles SET retired_at = ? "
                "WHERE bundle_id = ? AND version = ? AND retired_at IS NULL",
                (moment.isoformat(), bundle_id, version),
            ).rowcount
        if updated != 1:
            msg = (
                f"cannot retire {bundle_id} v{version}: no live published version matched. "
                "Someone retired it, or it was never published. The catalog on this "
                f"database holds {len(catalog)} live version(s)."
            )
            raise PolicyAuthoringError(msg)

    # -- read -----------------------------------------------------------------

    def rows(self) -> tuple[PublishedBundle, ...]:
        """Every stored version, live or retired, oldest id and version first."""
        return tuple(
            PublishedBundle(
                bundle_id=str(row["bundle_id"]),
                version=int(row["version"]),
                content_digest=str(row["content_digest"]),
                published_at=str(row["published_at"]),
                published_by=str(row["published_by"]),
                retired_at=None if row["retired_at"] is None else str(row["retired_at"]),
            )
            for row in self._store.query(
                "SELECT bundle_id, version, content_digest, published_at, published_by, "
                "retired_at FROM policy_bundles ORDER BY bundle_id, version"
            )
        )

    def catalog(self) -> PolicyCatalog:
        """The stored catalog: every live bundle, and every tombstone.

        A retired version is loaded *and* tombstoned, so the catalog can refuse a
        republish of it by name. Loading only live rows would make a retired
        version indistinguishable from one that never existed.
        """
        bundles: list[PolicyBundle] = []
        retired: list[tuple[str, int]] = []
        for row in self._store.query(
            "SELECT bundle_id, version, content_digest, document, retired_at "
            "FROM policy_bundles ORDER BY bundle_id, version"
        ):
            bundle = _bundle_from_row(str(row["document"]))
            if bundle.bundle_id != str(row["bundle_id"]) or bundle.version != int(row["version"]):
                msg = (
                    f"stored policy {row['bundle_id']} v{row['version']} carries a document "
                    f"that says it is {bundle.describe()}; the row and its content disagree, "
                    "so neither can be read as the policy that decided anything"
                )
                raise PolicyAuthoringError(msg)
            if bundle.content_digest != str(row["content_digest"]):
                msg = (
                    f"stored policy {row['bundle_id']} v{row['version']} records digest "
                    f"{str(row['content_digest'])[:12]} but its document hashes to "
                    f"{(bundle.content_digest or 'nothing')[:12]}. One of the two is wrong "
                    "and mayhem cannot tell which, so neither can be read as the policy "
                    "that decided anything"
                )
                raise PolicyAuthoringError(msg)
            bundles.append(bundle)
            if row["retired_at"] is not None:
                retired.append((bundle.bundle_id, bundle.version))
        return PolicyCatalog(bundles=tuple(bundles), retired=tuple(retired))

    def get(self, bundle_id: str, version: int) -> PolicyBundle:
        return self.catalog().get(bundle_id, version)

    def resolve(
        self, bundle_id: str, version: int | None = None, *, now: datetime | None = None
    ) -> ResolvedPolicy:
        """The bundle to decide under. Never silently substitutes a version."""
        return self.catalog().resolve(bundle_id, version, now=now or utc_now())

    def gate_inputs(
        self,
        plan: ExecutionPlan,
        bundle_id: str,
        *,
        now: datetime,
        version: int | None = None,
        **overrides: Any,
    ) -> Any:
        """:meth:`PolicyCatalog.gate_inputs`, over the stored catalog."""
        return self.catalog().gate_inputs(plan, bundle_id, now=now, version=version, **overrides)


def _adopt_created_at(document: Mapping[str, Any], catalog: PolicyCatalog) -> datetime | None:
    """The instant an existing version was authored at, or ``None`` for a new one.

    ``PolicyBundle.created_at`` defaults to ``utc_now`` and is inside the content
    digest, so a document that omits it hashes to something different every time
    it is read. Without this, replaying the same document would be reported as an
    immutable version rewritten, and the catalog's idempotence path could not be
    reached from any document that left the field out.

    A document that **states** its own ``created_at`` keeps it either way: the
    author pinned their intent, and a mismatch against the stored instant is
    exactly the "rewritten version" the immutability check is for.
    """
    if "created_at" in document:
        return None
    bundle_id = document.get("bundle_id")
    version = document.get("version")
    if not isinstance(bundle_id, str) or not isinstance(version, int):
        return None
    for bundle in catalog.bundles:
        if bundle.bundle_id == bundle_id and bundle.version == version:
            return bundle.created_at
    return None


def _canonical(bundle: PolicyBundle) -> str:
    """The bundle as canonical JSON, so a reload re-derives the same digest."""
    return json.dumps(bundle.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))


def _bundle_from_row(document: str) -> PolicyBundle:
    raw = json.loads(document)
    if not isinstance(raw, dict):
        msg = f"stored policy document is a {type(raw).__name__}, not an object"
        raise PolicyAuthoringError(msg)
    return bundle_from_mapping(raw)
