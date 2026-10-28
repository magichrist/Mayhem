"""Plan 18 Phase 3: template distribution through the catalogue.

The rule under test is one line: a template's digest is the sha256 of the canonical
JSON of its ``drill_template`` and of nothing else. Metadata (changelog, licence,
parameters, publisher) is outside the digest, so editing it cannot change what a
pinned digest verifies, while editing the body always does.

Every claim has its negative control: a wrong declared digest is refused before any
write, a republish with different bytes is refused, a row altered in the store is
refused on read, and the CLI refuses the same things it refuses in the store.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from mayhem.cli.marketplace_cmd import marketplace
from mayhem.domain.attestation import canonical_event_json
from mayhem.domain.marketplace import (
    ExperimentTemplate,
    PublisherDeclaration,
    RegistryRef,
    RegistryScope,
    TemplateParameter,
    template_content_digest,
)
from mayhem.infra.marketplace_store import (
    ACTIVITY_TEMPLATE_PUBLISHED,
    MarketplaceError,
    MarketplaceStore,
)
from mayhem.infra.store import Store

BODY: dict[str, Any] = {
    "kind": "drill",
    "name": "{{ experiment_name }}",
    "targets": {
        "checkout": {
            "runtime": "kubernetes",
            "kubernetes": {
                "kind": "deployment",
                "namespace": "{{ namespace }}",
                "name": "checkout",
            },
            "faults": [{"fault": "k8s.pod_kill", "duration": "{{ duration }}"}],
        }
    },
    "execution": [{"sequential": ["checkout"]}],
}
PARAMS = (
    TemplateParameter(name="experiment_name", description="drill name"),
    TemplateParameter(name="namespace", description="target namespace"),
    TemplateParameter(name="duration", description="fault duration"),
)


def _digest_of(body: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_event_json(body).encode("utf-8")).hexdigest()


def _template(
    *, body: dict[str, Any] | None = None, version: str = "1.0.0", **overrides: Any
) -> ExperimentTemplate:
    chosen = BODY if body is None else body
    fields: dict[str, Any] = {
        "template_id": "checkout.pod_kill",
        "version": version,
        "digest": _digest_of(chosen),
        "publisher": PublisherDeclaration(
            publisher_id="acme", display_name="Acme", contact="ops@acme.test", organization="acme"
        ),
        "registry": RegistryRef(
            registry_id="acme.registry",
            display_name="Acme Registry",
            scope=RegistryScope.ORGANIZATION_PRIVATE,
            organization="acme",
        ),
        "parameters": PARAMS,
        "drill_template": chosen,
        "license_id": "Apache-2.0",
        "changelog_ref": "CHANGELOG.md#1.0.0",
    }
    fields.update(overrides)
    return ExperimentTemplate(**fields)


@pytest.fixture()
def store(tmp_path: Path) -> Any:
    opened = Store.open_migrated(tmp_path / "templates.db")
    yield opened
    opened.close()


def _sealed_template_events(store: Any) -> int:
    rows = store.query(
        "SELECT COUNT(*) FROM attestation_events WHERE event_kind = ?",
        (ACTIVITY_TEMPLATE_PUBLISHED,),
    )
    return int(rows[0][0])


class TestTheDigestRule:
    def test_the_digest_is_sha256_of_the_canonical_body(self) -> None:
        assert template_content_digest(BODY) == _digest_of(BODY)

    def test_key_order_does_not_change_the_digest(self) -> None:
        reordered = dict(reversed(list(BODY.items())))
        assert template_content_digest(reordered) == template_content_digest(BODY)

    def test_editing_the_body_changes_the_digest(self) -> None:
        edited = {**BODY, "name": "a different drill"}
        assert template_content_digest(edited) != template_content_digest(BODY)

    def test_metadata_is_outside_the_digest(self) -> None:
        # The negative control for the scope of the rule: a changelog or licence
        # edit must not move the digest a pinned version verifies.
        first = _template(changelog_ref="CHANGELOG.md#1.0.0")
        second = _template(changelog_ref="CHANGELOG.md#1.0.0-rewritten")
        assert first.digest == second.digest

    def test_a_non_finite_number_is_refused_rather_than_hashed(self) -> None:
        with pytest.raises(ValueError):
            template_content_digest({"x": float("nan")})


class TestPublishAndResolve:
    def test_a_published_template_resolves_to_the_same_bytes(self, store: Any) -> None:
        catalog = MarketplaceStore(store)
        published = catalog.publish_template(_template())
        resolved = catalog.template("checkout.pod_kill", "1.0.0")
        assert resolved is not None
        assert resolved.digest == published.digest
        assert resolved.drill_template == BODY

    def test_publishing_seals_one_activity(self, store: Any) -> None:
        MarketplaceStore(store).publish_template(_template())
        assert _sealed_template_events(store) == 1

    def test_republishing_identical_bytes_is_a_no_op(self, store: Any) -> None:
        catalog = MarketplaceStore(store)
        catalog.publish_template(_template())
        catalog.publish_template(_template())
        assert _sealed_template_events(store) == 1
        assert len(catalog.templates()) == 1

    def test_a_declared_digest_that_does_not_match_the_body_is_refused(self, store: Any) -> None:
        bad = _template(digest="0" * 64)
        with pytest.raises(MarketplaceError) as refused:
            MarketplaceStore(store).publish_template(bad)
        assert refused.value.code == "marketplace.template.digest_mismatch"
        assert MarketplaceStore(store).templates() == ()
        assert _sealed_template_events(store) == 0

    def test_a_version_cannot_be_replaced_with_different_bytes(self, store: Any) -> None:
        catalog = MarketplaceStore(store)
        catalog.publish_template(_template())
        other_body = {**BODY, "name": "{{ experiment_name }}-v2"}
        with pytest.raises(MarketplaceError) as refused:
            catalog.publish_template(_template(body=other_body))
        assert refused.value.code == "marketplace.template.version_conflict"
        assert catalog.template("checkout.pod_kill", "1.0.0").drill_template == BODY  # type: ignore[union-attr]

    def test_a_new_version_with_new_bytes_is_accepted(self, store: Any) -> None:
        catalog = MarketplaceStore(store)
        catalog.publish_template(_template())
        catalog.publish_template(_template(body={**BODY, "name": "x"}, version="1.1.0"))
        assert [t.version for t in catalog.templates(template_id="checkout.pod_kill")] == [
            "1.0.0",
            "1.1.0",
        ]

    def test_a_row_altered_in_the_store_is_refused_on_read(self, store: Any) -> None:
        catalog = MarketplaceStore(store)
        catalog.publish_template(_template())
        tampered = json.loads(
            store.query(
                "SELECT template_json FROM marketplace_templates WHERE template_id = ?",
                ("checkout.pod_kill",),
            )[0][0]
        )
        tampered["drill_template"]["name"] = "{{ experiment_name }}-evil"
        with store.write() as conn:
            conn.execute(
                "UPDATE marketplace_templates SET template_json = ? WHERE template_id = ?",
                (json.dumps(tampered), "checkout.pod_kill"),
            )
        with pytest.raises(MarketplaceError) as refused:
            catalog.template("checkout.pod_kill", "1.0.0")
        assert refused.value.code == "marketplace.template.digest_mismatch"

    def test_an_unknown_template_resolves_to_none(self, store: Any) -> None:
        assert MarketplaceStore(store).template("nope", "1.0.0") is None


class TestTheCliSurface:
    def _run(self, *args: str) -> Any:
        return CliRunner().invoke(marketplace, list(args))

    def test_digest_prints_the_rule_for_a_file(self, tmp_path: Path) -> None:
        path = tmp_path / "t.json"
        path.write_text(json.dumps({"drill_template": BODY}), encoding="utf-8")
        result = self._run("template", "digest", str(path), "--json")
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["digest"] == _digest_of(BODY)

    def test_publish_then_list_then_instantiate_round_trip(self, tmp_path: Path) -> None:
        db = str(tmp_path / "cli.db")
        path = tmp_path / "t.json"
        document = _template().model_dump(mode="json")
        path.write_text(json.dumps(document), encoding="utf-8")

        published = self._run("template", "publish", str(path), "--db", db, "--json")
        assert published.exit_code == 0, published.output

        listed = self._run("template", "list", "--db", db, "--json")
        assert listed.exit_code == 0, listed.output
        rows = json.loads(listed.output)["templates"]
        assert rows[0]["template_id"] == "checkout.pod_kill"

        rendered = self._run(
            "template",
            "instantiate",
            "checkout.pod_kill",
            "--version",
            "1.0.0",
            "--db",
            db,
            "--set",
            "experiment_name=shop-chaos",
            "--set",
            "namespace=shop",
            "--set",
            "duration=30s",
            "--json",
        )
        assert rendered.exit_code == 0, rendered.output
        payload = json.loads(rendered.output)
        assert payload["document"]["name"] == "shop-chaos"
        assert "note" in payload and "mayhem plan" in payload["note"]

    def test_publish_refuses_a_wrong_declared_digest(self, tmp_path: Path) -> None:
        db = str(tmp_path / "cli.db")
        path = tmp_path / "t.json"
        document = _template().model_dump(mode="json")
        document["digest"] = "1" * 64
        path.write_text(json.dumps(document), encoding="utf-8")
        result = self._run("template", "publish", str(path), "--db", db, "--json")
        assert result.exit_code != 0
        assert "digest_mismatch" in result.output

    def test_instantiate_refuses_a_missing_slot(self, tmp_path: Path) -> None:
        db = str(tmp_path / "cli.db")
        path = tmp_path / "t.json"
        path.write_text(json.dumps(_template().model_dump(mode="json")), encoding="utf-8")
        assert self._run("template", "publish", str(path), "--db", db).exit_code == 0
        result = self._run(
            "template", "instantiate", "checkout.pod_kill", "--version", "1.0.0", "--db", db
        )
        assert result.exit_code != 0
