"""The Terraform surface over plan 08's API (docs/v1.1.0/16_CI_GITOPS_INTEGRATIONS.md,
Phase 3 — "Terraform plan/apply round-trips against the API in tests").

The API is a fake, and that is the point rather than a limitation to apologise
for: the property under test is that *mayhem's* decisions — create, no-op,
update, refuse-on-stale, refuse-on-unconfirmed — are correct given what the API
answers, and that needs a port whose answers can be arranged exactly. A real
API would make those cases depend on a network.

The suite is grouped by the finding each test pins:

* **an unreadable state is not an absent state.** Unbound, raising and
  wrong-shaped ports all refuse the plan (:data:`RULE_TF_STATE_UNREADABLE`)
  instead of planning a create. Planning a create against a state that could not
  be read is how an experiment gets silently re-created and its old
  attachments orphaned.
* **a ``None`` read means absent.** It is a reachable answer, it plans a create,
  and it is a different finding from unreachable — asserted as a distinct pair of
  cases rather than lumped together.
* **the round trip is exact.** plan → apply → read back yields the same
  resource, the same digest, and a conformance report with no reasons.
* **apply refuses on drift.** A write that lands between plan and apply is
  caught by the re-read, nothing is written, and the refusal says which digests
  disagreed. This is the negative control the plan names, expressed in the
  vocabulary Terraform actually uses.
* **a write the API does not echo back is unconfirmed.** A store that returns a
  *different* digest, or something that is not a resource at all, is refused:
  mayhem reports what it can prove rather than what it hoped.
* **credentials are refused in config**, because terraform state is plaintext.
"""

from __future__ import annotations

from typing import Any

import pytest

from mayhem.controller.terraform_provider import (
    ABSENT_DIGEST,
    ApiReach,
    ExperimentConfig,
    TerraformChange,
    TerraformRefusedError,
    api_reach,
    conformance_reasons,
    parse_import_id,
    render_hcl,
    terraform_apply,
    terraform_plan,
)
from mayhem.domain.api import ExperimentResource
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.experiments import DrillSpec

API_ENDPOINT = "https://mayhem.internal/api"


def _spec(name: str = "checkout-latency") -> DrillSpec:
    return DrillSpec.model_validate(
        {
            "kind": "drill",
            "name": name,
            "hypothesis": "p99 rises under packet loss",
            "containers": {"checkout": {"faults": [{"fault": "net.latency", "duration": "5s"}]}},
            "execution": [{"sequential": ["checkout"]}],
        }
    )


def _config(name: str = "checkout-latency", **overrides: Any) -> ExperimentConfig:
    fields: dict[str, Any] = {
        "name": name,
        "spec": _spec(name),
        "tf_label": "checkout_latency",
        "api_endpoint": API_ENDPOINT,
    }
    fields.update(overrides)
    return ExperimentConfig(**fields)


class _Store:
    """An in-memory API: three methods, and every failure mode on demand."""

    def __init__(self, present: dict[str, ExperimentResource] | None = None) -> None:
        self.present: dict[str, ExperimentResource] = dict(present or {})
        self.writes: list[ExperimentResource] = []
        self.deletes: list[str] = []
        self.raises_on_read = False
        self.read_returns: object = "unset"
        self.write_returns: object = "unset"

    def read_experiment(self, *, name: str) -> object | None:
        if self.raises_on_read:
            raise ConnectionError("connection refused")
        if self.read_returns != "unset":
            return self.read_returns
        return self.present.get(name)

    def write_experiment(self, *, resource: ExperimentResource) -> object:
        if self.write_returns != "unset":
            return self.write_returns
        self.present[resource.name] = resource
        self.writes.append(resource)
        return resource

    def delete_experiment(self, *, name: str) -> object:
        self.present.pop(name, None)
        self.deletes.append(name)
        return {"deleted": name}


# ── the port, and what its answers mean ──────────────────────────────────────


class TestApiReach:
    def test_a_resource_is_a_reachable_read(self) -> None:
        assert api_reach(ExperimentResource.of(_spec())) is ApiReach.REACHABLE

    def test_none_is_absent_not_unavailable(self) -> None:
        assert api_reach(None) is ApiReach.ABSENT

    def test_an_error_is_unavailable(self) -> None:
        assert api_reach(None, error=TimeoutError()) is ApiReach.UNAVAILABLE

    @pytest.mark.parametrize("answer", [{"name": "x"}, "checkout", 42], ids=["dict", "str", "int"])
    def test_a_wrong_shape_is_unavailable(self, answer: object) -> None:
        assert api_reach(answer) is ApiReach.UNAVAILABLE


# ── the configuration ─────────────────────────────────────────────────────────


class TestConfig:
    def test_an_unset_label_falls_back_to_the_experiment_name(self) -> None:
        assert _config(tf_label="").address == "mayhem_experiment.checkout-latency"

    def test_the_address_is_typed_from_the_label(self) -> None:
        assert _config().address == "mayhem_experiment.checkout_latency"

    def test_the_import_id_names_one_experiment(self) -> None:
        assert _config().import_id == "mayhem_experiment/checkout-latency"
        assert parse_import_id("mayhem_experiment/checkout-latency") == "checkout-latency"

    @pytest.mark.parametrize(
        "value",
        ["checkout-latency", "mayhem_experiment/", "mayhem_experiment/a/b", ""],
        ids=["bare-name", "empty-name", "two-slashes", "empty"],
    )
    def test_a_malformed_import_id_is_refused(self, value: str) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            parse_import_id(value)
        assert excinfo.value.rule == "terraform.invalid_resource_label"

    def test_a_token_in_config_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            _config(api_token="ghp-not-a-real-token")
        assert excinfo.value.rule == "terraform.credential_in_config"
        assert "plaintext" in str(excinfo.value)

    def test_a_resource_whose_name_disagrees_with_its_spec_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            ExperimentConfig(name="checkout-latency", spec=_spec("other-name"))
        assert excinfo.value.rule == "terraform.invalid_resource_label"

    @pytest.mark.parametrize("label", ["Checkout", "1checkout", "checkout latency", "a$b"])
    def test_an_invalid_terraform_label_is_refused(self, label: str) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            _config(tf_label=label)
        assert excinfo.value.rule == "terraform.invalid_resource_label"

    def test_the_rendered_hcl_carries_the_digest_and_no_token(self) -> None:
        rendered = render_hcl(_config())
        assert _config().spec_digest in rendered
        assert "mayhem_experiment" in rendered
        assert "ghp-" not in rendered
        assert "api_token" not in rendered

    def test_the_rendered_hcl_is_deterministic(self) -> None:
        assert render_hcl(_config()) == render_hcl(_config())


# ── plan ──────────────────────────────────────────────────────────────────────


class TestPlan:
    def test_an_absent_experiment_plans_a_create(self) -> None:
        plan = terraform_plan(_config(), port=_Store())
        assert plan.change is TerraformChange.CREATE
        assert plan.observed_digest == ABSENT_DIGEST
        assert plan.has_change

    def test_a_matching_experiment_plans_nothing(self) -> None:
        resource = ExperimentResource.of(_spec())
        plan = terraform_plan(_config(), port=_Store({"checkout-latency": resource}))
        assert plan.change is TerraformChange.NO_OP
        assert not plan.has_change

    def test_a_differing_experiment_plans_an_update(self) -> None:
        stored = ExperimentResource.of(
            _spec().model_copy(update={"hypothesis": "an older hypothesis"})
        )
        plan = terraform_plan(_config(), port=_Store({"checkout-latency": stored}))
        assert plan.change is TerraformChange.UPDATE

    def test_the_plan_digest_is_stable_for_the_same_inputs(self) -> None:
        first = terraform_plan(_config(), port=_Store())
        second = terraform_plan(_config(), port=_Store())
        assert first.plan_digest == second.plan_digest

    def test_the_plan_digest_moves_when_the_observed_state_does(self) -> None:
        empty = terraform_plan(_config(), port=_Store())
        stored = terraform_plan(
            _config(),
            port=_Store({"checkout-latency": ExperimentResource.of(_spec())}),
        )
        assert empty.plan_digest != stored.plan_digest

    @pytest.mark.parametrize("mode", ["unbound", "raising", "wrong-shape"])
    def test_an_unreadable_state_is_refused_not_treated_as_absent(self, mode: str) -> None:
        store: Any
        if mode == "unbound":
            store = None
        elif mode == "raising":
            store = _Store()
            store.raises_on_read = True
        else:
            store = _Store()
            store.read_returns = {"name": "checkout-latency"}
        with pytest.raises(TerraformRefusedError) as excinfo:
            terraform_plan(_config(), port=store)
        assert excinfo.value.rule == "terraform.state_unreadable"
        assert "not an absent state" in str(excinfo.value)

    def test_destroying_something_absent_is_refused(self) -> None:
        with pytest.raises(TerraformRefusedError) as excinfo:
            terraform_plan(_config(), port=_Store(), destroy=True)
        assert excinfo.value.rule == "terraform.state_unreadable"


# ── apply: the round trip ─────────────────────────────────────────────────────


class TestRoundTrip:
    def test_create_apply_read_back_is_exact(self) -> None:
        store = _Store()
        config = _config()
        plan = terraform_plan(config, port=store)
        result = terraform_apply(plan, port=store)

        assert result.confirmed is True
        assert result.change is TerraformChange.CREATE
        stored = store.present["checkout-latency"]
        assert stored.spec_digest == config.spec_digest
        assert conformance_reasons(config, stored) == ()
        assert result.resource.spec_digest == stored.spec_digest

    def test_update_apply_replaces_the_stored_spec(self) -> None:
        stored = ExperimentResource.of(_spec().model_copy(update={"hypothesis": "older"}))
        store = _Store({"checkout-latency": stored})
        config = _config()
        plan = terraform_plan(config, port=store)
        assert plan.change is TerraformChange.UPDATE
        result = terraform_apply(plan, port=store)
        assert store.present["checkout-latency"].spec_digest == config.spec_digest
        assert conformance_reasons(config, result.resource) == ()

    def test_a_no_op_writes_nothing(self) -> None:
        store = _Store({"checkout-latency": ExperimentResource.of(_spec())})
        plan = terraform_plan(_config(), port=store)
        result = terraform_apply(plan, port=store)
        assert store.writes == []
        assert result.confirmed is True

    def test_destroy_deletes_and_admits_there_is_nothing_left(self) -> None:
        store = _Store({"checkout-latency": ExperimentResource.of(_spec())})
        plan = terraform_plan(_config(), port=store, destroy=True)
        result = terraform_apply(plan, port=store)
        assert store.deletes == ["checkout-latency"]
        assert result.confirmed is False
        assert "no current resource" in result.detail


class TestApplyRefuses:
    def test_drift_between_plan_and_apply_is_refused_and_nothing_is_written(self) -> None:
        store = _Store()
        config = _config()
        plan = terraform_plan(config, port=store)
        # Somebody else creates the experiment between the plan and the apply.
        store.present["checkout-latency"] = ExperimentResource.of(
            _spec().model_copy(update={"hypothesis": "written by another pipeline"})
        )
        with pytest.raises(TerraformRefusedError) as excinfo:
            terraform_apply(plan, port=store)
        assert excinfo.value.rule == "terraform.plan_stale"
        assert store.writes == []
        assert "Re-plan" in str(excinfo.value)

    def test_an_unreadable_state_at_apply_time_is_refused(self) -> None:
        store = _Store()
        plan = terraform_plan(_config(), port=store)
        store.raises_on_read = True
        with pytest.raises(TerraformRefusedError) as excinfo:
            terraform_apply(plan, port=store)
        assert excinfo.value.rule == "terraform.state_unreadable"

    def test_a_write_that_echoes_a_different_digest_is_unconfirmed(self) -> None:
        store = _Store()
        plan = terraform_plan(_config(), port=store)
        store.write_returns = ExperimentResource.of(
            _spec().model_copy(update={"hypothesis": "something else entirely"})
        )
        with pytest.raises(TerraformRefusedError) as excinfo:
            terraform_apply(plan, port=store)
        assert excinfo.value.rule == "terraform.write_unconfirmed"
        assert "unconfirmed write" in str(excinfo.value)

    @pytest.mark.parametrize("answer", [{"ok": True}, "stored", None], ids=["dict", "str", "none"])
    def test_a_write_in_the_wrong_shape_is_unconfirmed(self, answer: object) -> None:
        store = _Store()
        plan = terraform_plan(_config(), port=store)
        store.write_returns = answer
        with pytest.raises(TerraformRefusedError) as excinfo:
            terraform_apply(plan, port=store)
        assert excinfo.value.rule == "terraform.write_unconfirmed"

    def test_a_raising_write_is_unconfirmed_not_silently_ignored(self) -> None:
        store = _Store()
        plan = terraform_plan(_config(), port=store)

        class _Exploding(type(store)):  # type: ignore[misc]
            def write_experiment(self, *, resource: ExperimentResource) -> object:
                raise RuntimeError("disk full")

        with pytest.raises(TerraformRefusedError) as excinfo:
            terraform_apply(plan, port=_Exploding())
        assert excinfo.value.rule == "terraform.write_unconfirmed"


# ── conformance ───────────────────────────────────────────────────────────────


class TestConformance:
    def test_a_matching_experiment_conforms(self) -> None:
        config = _config()
        assert conformance_reasons(config, ExperimentResource.of(_spec())) == ()

    def test_an_absent_experiment_does_not_conform(self) -> None:
        reasons = conformance_reasons(_config(), None)
        assert len(reasons) == 1
        assert "no experiment named" in reasons[0]

    def test_a_wrong_shape_does_not_conform_and_says_it_cannot_evaluate(self) -> None:
        reasons = conformance_reasons(_config(), {"name": "checkout-latency"})
        assert len(reasons) == 1
        assert "conformance cannot be evaluated" in reasons[0]

    def test_a_drifted_spec_is_named_by_digest(self) -> None:
        reasons = conformance_reasons(
            _config(),
            ExperimentResource.of(_spec().model_copy(update={"hypothesis": "older"})),
        )
        assert len(reasons) == 1
        assert "the stored spec digest is" in reasons[0]
