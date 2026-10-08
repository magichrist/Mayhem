"""``mayhem policy``: the authoring and explanation surface (plan 07 Phase 3).

Plan 07 built the vocabulary, put policy inside the real gate, and sealed what
the gate decided. Phase 4 recorded the hole this file closes: **nothing authored,
stored, or selected a bundle.** The authoring module was an in-memory registry
with no IO, so a policy an operator could write down could not be kept, and every
run still reached the gate with the older ``config.py`` block deciding alone.

What is here, and why each part is asserted twice:

* **CRUD over a real migrated database.** ``publish``/``list``/``show``/
  ``resolve``/``retire`` are driven through the CLI rather than by calling the
  store, because the surface is what the plan asked for and the exit codes are
  what a pipeline reads. Immutability, version ordering and retirement are
  each proved from the refusing side.
* **The plan's own DENY example is the engine's output.** That is the phase's
  acceptance criterion, and it is checkable: the block in
  ``docs/v1.1.0/07_POLICY_SAFETY_ENGINE.md`` is compared to what
  ``explain_refusal`` renders for a real gate result. A hand-written example and
  an engine that renders differently now fail here instead of quietly agreeing
  with each other in review.
* **An explanation mutates nothing.** ``explain`` goes through Phase 2's
  ``simulate_gate``, so asking "would this be denied" cannot spend a budget or
  take a lock. Asserted by re-reading the store afterwards, not by a flag the
  command prints about itself.
* **A missing policy is a refusal.** With nothing published for the id,
  ``explain`` exits with a usage error. "Decide under no policy" is the one
  answer this surface must not be able to give.
"""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Any, cast

import yaml
from click.testing import CliRunner

from mayhem.cli.app import app
from mayhem.cli.exit_codes import ExitCode
from mayhem.domain.experiments import (
    ExecutionPlan,
    ExperimentKind,
    InjectFault,
    PlannedFault,
    PlannedStep,
    ResolvedTarget,
)
from mayhem.domain.topology import NodeKind, TargetSelector

if TYPE_CHECKING:
    from pathlib import Path

PLAN_DOC = "docs/v1.1.0/07_POLICY_SAFETY_ENGINE.md"

#: The bundle the surface publishes: one approval-level rule (so the plan's own
#: `Required:` line is produced) and one family rule (so a second rule shows up
#: in the evaluated list and the refusal names only the one that fired).
BUNDLE_YAML = """bundle_id: prod
version: 1
description: production policy
default_effect: allow
rules:
  - rule_id: prod.critical_needs_two_approvals
    dimension: approval_level
    operator: not_in
    values: [sre, service_owner]
    effect: deny
    reason: production policy forbids critical faults without two approvals.
    remediation: collect SRE and service owner approvals
  - rule_id: prod.storage_needs_one_approval
    dimension: fault_family
    operator: in
    values: [storage]
    effect: deny
    reason: production policy forbids storage faults without an SRE approval.
    remediation: collect an SRE approval
"""


def _repo_root() -> Path:
    from pathlib import Path

    return Path(__file__).resolve().parents[2]


def _run(*args: str) -> Any:
    return CliRunner().invoke(app, list(args), catch_exceptions=False)


def _payload(result: Any) -> dict[str, Any]:
    return cast("dict[str, Any]", json.loads(result.output))


def _plan(fault_id: str = "net.latency") -> ExecutionPlan:
    selector = TargetSelector(kind=NodeKind.SERVICE, expr="api")
    return ExecutionPlan(
        run_id="r-policy-surface",
        kind=ExperimentKind.DRILL,
        steps=(
            PlannedStep(
                id="s1",
                seq=0,
                raw_action=InjectFault(fault=fault_id, selectors=(selector,), duration=5.0),
                fault=PlannedFault(
                    fault_id=fault_id,
                    targets=(ResolvedTarget(selector=selector, node_ids=frozenset({"n-a"})),),
                    duration=5.0,
                ),
            ),
        ),
        config_snapshot_id="c",
        topology_snapshot_id="t",
        environment_fingerprint="f",
        policy_id="default",
    )


def _write_plan(tmp_path: Path, fault_id: str = "net.latency") -> str:
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(_plan(fault_id).model_dump(mode="json"), indent=2), encoding="utf-8")
    return str(path)


def _write_bundle(tmp_path: Path, text: str = BUNDLE_YAML, name: str = "prod.yaml") -> str:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return str(path)


def _db(tmp_path: Path) -> str:
    return str(tmp_path / "policy.db")


def _published(tmp_path: Path, *options: str) -> str:
    """A database with the bundle above published, ready for the read commands."""
    db = _db(tmp_path)
    result = _run("policy", "publish", _write_bundle(tmp_path), "--db", db, *options)
    assert result.exit_code == int(ExitCode.SUCCESS), result.output
    return db


class TestTheSurfaceIsReachable:
    def test_the_group_renders_help(self) -> None:
        result = _run("policy", "--help")

        assert result.exit_code == 0
        for verb in ("publish", "list", "show", "retire", "resolve", "explain"):
            assert verb in result.output

    def test_every_subcommand_renders_help(self) -> None:
        for verb in ("publish", "list", "show", "retire", "resolve", "explain"):
            result = _run("policy", verb, "--help")
            assert result.exit_code == 0, verb
            assert "Usage:" in result.output

    def test_an_empty_catalog_says_so_rather_than_printing_nothing(self, tmp_path: Path) -> None:
        """A blank table would read as "there is no policy" either way."""
        result = _run("policy", "list", "--db", _db(tmp_path))

        assert result.exit_code == 0
        assert "no policy bundle is published" in result.output


class TestCreateAndRead:
    def test_publish_pins_the_digest_and_names_the_author(self, tmp_path: Path) -> None:
        db = _published(tmp_path, "--by", "sre-oncall")
        result = _run("policy", "list", "--db", db, "--json")

        payload = _payload(result)
        row = payload["bundles"][0]
        assert row["bundle_id"] == "prod"
        assert row["version"] == 1
        assert len(row["content_digest"]) == 64
        assert row["published_by"] == "sre-oncall"
        assert row["state"] == "published"

    def test_a_published_version_survives_a_reopen_with_its_digest(self, tmp_path: Path) -> None:
        """The defect this phase's storage half would have shipped without.

        ``bundle_from_mapping`` used to drop a stated ``content_digest``, so every
        bundle read back out of storage arrived with ``content_digest=None`` — no
        digest for an approval to name, and the pin the store records meaningless.
        """
        db = _published(tmp_path)
        listed = _payload(_run("policy", "list", "--db", db, "--json"))["bundles"][0]
        shown = _payload(_run("policy", "show", "prod", "--db", db, "--json"))

        assert shown["content_digest"] == listed["content_digest"]

    def test_a_document_whose_digest_disagrees_with_its_content_is_refused(
        self, tmp_path: Path
    ) -> None:
        tampered = BUNDLE_YAML.replace(
            "description: production policy",
            "description: production policy, but the digest says otherwise",
        )
        payload = {"bundle_id": "prod", "version": 1, "content_digest": "0" * 64}
        document = yaml.safe_load(tampered)
        document.update(payload)
        path = tmp_path / "tampered.yaml"
        path.write_text(yaml.safe_dump(document), encoding="utf-8")

        result = _run("policy", "publish", str(path), "--db", _db(tmp_path))

        assert result.exit_code == int(ExitCode.SAFETY_REFUSAL)
        assert "not valid" in result.output

    def test_resolve_names_the_version_it_took(self, tmp_path: Path) -> None:
        db = _published(tmp_path)
        payload = _payload(_run("policy", "resolve", "prod", "--db", db, "--json"))

        assert payload["version"] == 1
        assert payload["resolved_by"] == "newest published"
        assert len(payload["content_digest"]) == 64

    def test_resolve_never_substitutes_the_version_that_was_asked_for(self, tmp_path: Path) -> None:
        """Two-sided against the case above: naming a version is a contract."""
        db = _published(tmp_path)

        result = _run("policy", "resolve", "prod", "--version", "7", "--db", db)

        assert result.exit_code == int(ExitCode.VALIDATION_ERROR)
        assert "is published" in result.output

    def test_an_unknown_bundle_is_a_usage_error(self, tmp_path: Path) -> None:
        result = _run("policy", "resolve", "nope", "--db", _db(tmp_path))

        assert result.exit_code == int(ExitCode.VALIDATION_ERROR)
        assert "no policy version" in result.output


class TestUpdateAndDelete:
    def test_an_amendment_is_a_new_version(self, tmp_path: Path) -> None:
        db = _published(tmp_path)
        second = BUNDLE_YAML.replace("version: 1", "version: 2")

        assert (
            _run(
                "policy", "publish", _write_bundle(tmp_path, second, "prod-v2.yaml"), "--db", db
            ).exit_code
            == 0
        )

        versions = [
            row["version"]
            for row in _payload(_run("policy", "list", "--db", db, "--json"))["bundles"]
        ]
        assert versions == [1, 2]

    def test_republishing_a_version_with_different_content_is_refused(self, tmp_path: Path) -> None:
        db = _published(tmp_path)
        rewritten = BUNDLE_YAML.replace("description: production policy", "description: rewritten")

        result = _run("policy", "publish", _write_bundle(tmp_path, rewritten), "--db", db)

        assert result.exit_code == int(ExitCode.SAFETY_REFUSAL)
        assert "immutable" in result.output

    def test_republishing_the_identical_document_is_idempotent(self, tmp_path: Path) -> None:
        """The other side of immutability: a replayed publish is not an error."""
        db = _published(tmp_path)

        result = _run("policy", "publish", _write_bundle(tmp_path), "--db", db)

        assert result.exit_code == 0
        assert _payload(_run("policy", "list", "--db", db, "--json"))["count"] == 1

    def test_retire_tombstones_rather_than_deletes(self, tmp_path: Path) -> None:
        db = _published(tmp_path)

        result = _run("policy", "retire", "prod", "--version", "1", "--db", db)

        assert result.exit_code == 0
        rows = _payload(_run("policy", "list", "--db", db, "--json"))["bundles"]
        assert rows[0]["state"] == "retired"
        assert rows[0]["content_digest"], "a retired version keeps the digest a record names"

    def test_a_retired_version_cannot_be_resolved_for_a_new_run(self, tmp_path: Path) -> None:
        db = _published(tmp_path)
        second = BUNDLE_YAML.replace("version: 1", "version: 2")
        _run("policy", "publish", _write_bundle(tmp_path, second, "prod-v2.yaml"), "--db", db)
        _run("policy", "retire", "prod", "--version", "1", "--db", db)

        newest = _payload(_run("policy", "resolve", "prod", "--db", db, "--json"))

        assert newest["version"] == 2

    def test_a_retired_version_cannot_be_republished(self, tmp_path: Path) -> None:
        db = _published(tmp_path)
        _run("policy", "retire", "prod", "--version", "1", "--db", db)

        result = _run("policy", "publish", _write_bundle(tmp_path), "--db", db)

        assert result.exit_code == int(ExitCode.SAFETY_REFUSAL)
        assert "retired" in result.output

    def test_retiring_a_version_nobody_published_is_refused(self, tmp_path: Path) -> None:
        db = _published(tmp_path)

        result = _run("policy", "retire", "prod", "--version", "9", "--db", db)

        assert result.exit_code == int(ExitCode.SAFETY_REFUSAL)
        assert "no such version" in result.output

    def test_retiring_twice_is_refused_rather_than_silently_accepted(self, tmp_path: Path) -> None:
        """A tombstone for something already retired asserts a change that did not happen."""
        db = _published(tmp_path)
        _run("policy", "retire", "prod", "--version", "1", "--db", db)

        result = _run("policy", "retire", "prod", "--version", "1", "--db", db)

        assert result.exit_code == int(ExitCode.SAFETY_REFUSAL)


class TestExplain:
    def test_a_denial_exits_non_zero_and_names_the_rule(self, tmp_path: Path) -> None:
        db = _published(tmp_path)

        result = _run(
            "policy", "explain", _write_plan(tmp_path), "--policy", "prod", "--db", db, "--json"
        )

        assert result.exit_code == int(ExitCode.SAFETY_REFUSAL)
        payload = _payload(result)
        assert payload["verdict"] == "DENY"
        assert payload["rule_ids"] == ["prod.critical_needs_two_approvals"]

    def test_the_reason_is_the_rule_authors_own_words(self, tmp_path: Path) -> None:
        db = _published(tmp_path)

        payload = _payload(
            _run(
                "policy", "explain", _write_plan(tmp_path), "--policy", "prod", "--db", db, "--json"
            )
        )

        assert payload["reason"].startswith(
            "production policy forbids critical faults without two approvals."
        )

    def test_it_reports_the_policy_and_digest_it_decided_under(self, tmp_path: Path) -> None:
        db = _published(tmp_path)
        listed = _payload(_run("policy", "list", "--db", db, "--json"))["bundles"][0]

        payload = _payload(
            _run(
                "policy", "explain", _write_plan(tmp_path), "--policy", "prod", "--db", db, "--json"
            )
        )

        assert payload["bundle_id"] == "prod"
        assert payload["bundle_version"] == 1
        assert payload["policy_digest"] == listed["content_digest"]

    def test_it_mutates_nothing(self, tmp_path: Path) -> None:
        """Not by believing the flag the command prints: by re-reading the store."""
        from mayhem.infra.policy_store import PolicyStore
        from mayhem.infra.store import Store

        db = _published(tmp_path)
        _run("policy", "explain", _write_plan(tmp_path), "--policy", "prod", "--db", db)

        store = Store.open_migrated(db)
        try:
            catalog = PolicyStore(store).catalog()
        finally:
            store.close()

        assert len(catalog.bundles) == 1
        assert catalog.retired == ()
        assert catalog.bundles[0].version == 1

    def test_every_evaluated_rule_is_listed_not_only_the_one_that_fired(
        self, tmp_path: Path
    ) -> None:
        db = _published(tmp_path)

        result = _run("policy", "explain", _write_plan(tmp_path), "--policy", "prod", "--db", db)

        assert "Rules (2 evaluated, 1 matched):" in result.output

    def test_an_unpublished_bundle_is_a_refusal_not_a_default(self, tmp_path: Path) -> None:
        db = _db(tmp_path)

        result = _run("policy", "explain", _write_plan(tmp_path), "--policy", "prod", "--db", db)

        assert result.exit_code == int(ExitCode.VALIDATION_ERROR)
        assert "no policy version" in result.output

    def test_an_unreadable_plan_is_refused_rather_than_explained(self, tmp_path: Path) -> None:
        """An explanation of a decision mayhem did not evaluate is fiction."""
        db = _published(tmp_path)
        path = tmp_path / "broken.json"
        path.write_text('{"steps": "not a plan"}', encoding="utf-8")

        result = _run("policy", "explain", str(path), "--policy", "prod", "--db", db)

        assert result.exit_code == int(ExitCode.VALIDATION_ERROR)
        assert "not a plan mayhem can read" in result.output

    def test_an_allowed_plan_exits_zero_and_omits_the_required_line(self, tmp_path: Path) -> None:
        """Two-sided: an artifact that always printed `Required:` would be noise."""
        db = _published(tmp_path)
        plan = _write_plan(tmp_path)

        result = _run(
            "policy",
            "explain",
            plan,
            "--policy",
            "prod",
            "--db",
            db,
            "--approval-held",
            "sre",
            "--approval-held",
            "service_owner",
            "--json",
        )

        assert result.exit_code == int(ExitCode.SUCCESS)
        payload = _payload(result)
        assert payload["verdict"] == "ALLOW"
        assert payload["required_approvals"] == []
        assert "Required:" not in payload["rendered"]


class TestTheDocumentedExampleIsTheEngines:
    """Plan 07 Phase 3's acceptance criterion, made checkable.

    The phase says the DENY block in the plan is "produced by the engine
    verbatim, not hand-written". A comment cannot enforce that; comparing the
    two texts can, and it fails the moment either drifts.
    """

    @staticmethod
    def _documented_block() -> list[str]:
        body = _repo_root().joinpath(PLAN_DOC).read_text(encoding="utf-8")
        match = re.search(r"```text\n(DENY\n(?:.*\n)*?)```", body)
        assert match is not None, "the plan must still carry its Example result block"
        return match.group(1).splitlines()

    @staticmethod
    def _engine_block() -> list[str]:
        from mayhem.domain.common import utc_now
        from mayhem.domain.policy_authoring import (
            bundle_from_mapping,
            explain_decision,
            with_pending_approvals,
        )
        from mayhem.domain.policy_gate import PolicyGateInputs, simulate_gate

        bundle = bundle_from_mapping(yaml.safe_load(BUNDLE_YAML))
        inputs = with_pending_approvals(PolicyGateInputs(bundle=bundle, now=utc_now()))
        result = simulate_gate(_plan(), inputs)
        return explain_decision(result, plan_digest="abc123", bundle=bundle).splitlines()

    def test_the_engine_renders_the_plan_block_verbatim(self) -> None:
        documented = self._documented_block()
        engine = self._engine_block()

        assert documented[0] == engine[0] == "DENY"
        assert documented[1] == engine[1]
        assert documented[2] == engine[2]
        assert documented[-1].startswith("Plan digest: ")

    def test_the_levels_are_rendered_sorted_so_two_runs_compare(self) -> None:
        """The plan's example and the engine agree because the engine sorts.

        If the sort were dropped, ``SRE`` and ``service owner`` would swap places
        depending on the rule's authored order, and an explanation a reader is
        comparing between two runs would reorder itself.
        """
        engine = self._engine_block()

        assert engine[2] == "Required: service owner + SRE."

    def test_and_the_document_block_is_exactly_four_lines(self) -> None:
        """An example that grew a fifth line would be a different artifact."""
        assert len(self._documented_block()) == 4
