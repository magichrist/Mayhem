"""v1.1.0 plan 18 Phase 4's second clause: templates are authoring convenience.

Phase 4 reads: *"template-instantiated experiments compile through the standard
planner; a template is authoring convenience, never a gate bypass"*, with the
acceptance criterion *"an experiment instantiated from a template is
indistinguishable downstream from an authored one."*

That clause was unreachable while no template artifact type existed — the plan
puts "Experiment templates and scenario packs (gap 33) distributed as versioned
artifacts" in Phase 3, and Phase 3 landed search/inspect/install but no template
type. `domain/marketplace.py` now carries one, so the criterion can finally be
stated as a test, and this file states it.

The acceptance test is `TestTemplateParity`: a plan compiled from
`instantiate_spec(...)` is compared, step for step, against a plan compiled from
the *authored* document a human would have written by hand. Parity is asserted
as frozen **shape** rather than byte equality, for the reason
`test_k8s_crds.py` gives: `_plan_target_faults` mints a `grp-<uuid>` per
compilation, so two compilations of one spec differ in group ids by
construction, and a byte-equality test would fail on correct code.

The stronger claim — *never a gate bypass* — is structural rather than
asserted here: `ExperimentTemplate` has no `run`/`execute`/`plan`/`dispatch`
method, `instantiate_spec` returns a `DrillSpec`, and `plan_drill` is the only
route from a `DrillSpec` to an `ExecutionPlan`. `TestNoSecondDoor` pins that by
asserting the absence of every such method, so a future "convenience" path
cannot appear without failing this file.

Honesty note: nothing here touches a registry, a cluster, or a runtime. The
publisher on every fixture is a **declaration** and no signature is verified —
`SIGNATURE_VERIFICATION_IMPLEMENTED` remains `False` and
`TestTemplatesCarryNoTrustClaim` re-asserts it for the new type.
"""

from __future__ import annotations

import hashlib
from typing import Any

import pytest

from mayhem.controller.planner import plan_drill
from mayhem.domain import marketplace
from mayhem.domain.errors import DomainError, InvariantViolationError
from mayhem.domain.experiments import DrillSpec
from mayhem.domain.marketplace import (
    ArtifactDeclarationError,
    ExperimentTemplate,
    PublisherDeclaration,
    RegistryRef,
    RegistryScope,
    TemplateInstantiationError,
    TemplateParameter,
    instantiate_spec,
    render_template,
    template_parameters,
    unfilled_placeholders,
)
from mayhem.domain.topology import TopologyGraph

RUN_ID = "run-template-1"
SNAPSHOTS = {
    "config_snapshot_id": "cfg-1",
    "topology_snapshot_id": "topo-1",
    "environment_fingerprint": "fp-1",
}

# The authored document a person would have written by hand, with every
# placeholder already filled in. Parity is measured against *this*.
AUTHORED_BODY: dict[str, Any] = {
    "kind": "drill",
    "name": "checkout-chaos",
    "targets": {
        "checkout": {
            "runtime": "kubernetes",
            "kubernetes": {
                "kind": "deployment",
                "namespace": "shop",
                "name": "checkout",
            },
            "faults": [{"fault": "k8s.pod_kill", "duration": "30s"}],
        }
    },
    "execution": [{"sequential": ["checkout"]}],
}

# The same document as a publisher ships it: the three variable parts are slots.
TEMPLATE_BODY: dict[str, Any] = {
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

VALUES = {"experiment_name": "checkout-chaos", "namespace": "shop", "duration": "30s"}

FORBIDDEN_ROUTES = ("run", "execute", "plan", "dispatch", "execute_plan", "start")


def _digest(seed: bytes) -> str:
    return hashlib.sha256(seed).hexdigest()


def _publisher() -> PublisherDeclaration:
    return PublisherDeclaration(
        publisher_id="acme",
        display_name="Acme",
        contact="ops@acme.test",
        organization="acme",
    )


def _registry() -> RegistryRef:
    return RegistryRef(
        registry_id="acme.registry",
        display_name="Acme Registry",
        scope=RegistryScope.ORGANIZATION_PRIVATE,
        organization="acme",
    )


def _template(**overrides: Any) -> ExperimentTemplate:
    params = (
        TemplateParameter(name="experiment_name", description="drill name"),
        TemplateParameter(name="namespace", description="target namespace"),
        TemplateParameter(name="duration", description="fault duration"),
    )
    template: dict[str, Any] = {
        "template_id": "checkout.pod_kill",
        "version": "1.0.0",
        "digest": _digest(b"checkout.pod_kill@1.0.0"),
        "publisher": _publisher(),
        "registry": _registry(),
        "parameters": params,
        "drill_template": TEMPLATE_BODY,
        "license_id": "Apache-2.0",
        "changelog_ref": "CHANGELOG.md#1.0.0",
    }
    template.update(overrides)
    return ExperimentTemplate(**template)


def _graph() -> TopologyGraph:
    """An empty plan-time graph: a targeted k8s drill stays logically pinned."""
    return TopologyGraph(nodes=(), edges=())


def _frozen_shape(plan: object) -> tuple[tuple[object, ...], ...]:
    """The deterministic content of a frozen plan, mirroring test_k8s_crds."""
    steps = getattr(plan, "steps", ())
    shape: list[tuple[object, ...]] = []
    for step in steps:
        fault = getattr(step, "fault", None)
        if fault is None:
            shape.append(("non-fault", getattr(step, "id", "")))
            continue
        target = getattr(fault, "target", None)
        authority = None
        if target is not None:
            authority = (
                getattr(target, "logical_id", ""),
                getattr(target, "runtime", ""),
                getattr(target, "kind", ""),
                dict(getattr(target, "authority", {}) or {}),
            )
        shape.append(
            (
                getattr(step, "seq", 0),
                getattr(fault, "fault_id", ""),
                authority,
                dict(getattr(fault, "params", {}) or {}),
                str(getattr(fault, "duration", "")),
            )
        )
    return tuple(shape)


def _authored_plan():
    return plan_drill(RUN_ID, DrillSpec.model_validate(AUTHORED_BODY), _graph(), **SNAPSHOTS)


def _instantiated_plan():
    spec = instantiate_spec(_template(), VALUES)
    assert isinstance(spec, DrillSpec)
    return plan_drill(RUN_ID, spec, _graph(), **SNAPSHOTS)


# ── acceptance: the two are indistinguishable ─────────────────────────────────
class TestTemplateParity:
    def test_an_instantiated_template_compiles_to_the_authored_plan(self) -> None:
        assert _frozen_shape(_instantiated_plan()) == _frozen_shape(_authored_plan())

    def test_instantiation_returns_the_same_type_a_yaml_file_returns(self) -> None:
        # The load-bearing fact: `parse_drill` and `instantiate_spec` agree on
        # the type, so nothing downstream has a second thing to handle.
        from mayhem.spec import parse_drill

        parsed = parse_drill(AUTHORED_BODY)
        assert isinstance(parsed, DrillSpec)
        assert type(instantiate_spec(_template(), VALUES)) is type(parsed)

    def test_the_compiled_plan_carries_the_real_workload_identity(self) -> None:
        plan = _instantiated_plan()
        (step,) = [s for s in plan.steps if s.fault is not None]
        assert step.fault is not None and step.fault.fault_id == "k8s.pod_kill"
        assert step.fault.target is not None
        assert step.fault.target.authority["namespace"] == "shop"

    def test_different_values_give_a_different_plan(self) -> None:
        """The control for the parity test above.

        Without it, "the two plans match" is satisfiable by a template that
        ignores its parameters entirely — which is the failure a parity test
        cannot see on its own.
        """
        other = instantiate_spec(_template(), {**VALUES, "namespace": "staging", "duration": "5s"})
        assert isinstance(other, DrillSpec)
        plan = plan_drill(RUN_ID, other, _graph(), **SNAPSHOTS)
        assert _frozen_shape(plan) != _frozen_shape(_authored_plan())


class TestNoSecondDoor:
    """A template is convenience, so it has no route to execution of its own."""

    @pytest.mark.parametrize("name", FORBIDDEN_ROUTES)
    def test_the_template_exposes_no_execution_route(self, name: str) -> None:
        assert not hasattr(_template(), name)

    def test_instantiate_returns_a_spec_not_a_plan(self) -> None:
        rendered = instantiate_spec(_template(), VALUES)
        assert isinstance(rendered, DrillSpec)
        assert not hasattr(rendered, "steps")

    @pytest.mark.parametrize("name", FORBIDDEN_ROUTES)
    def test_the_module_exposes_no_execution_helper(self, name: str) -> None:
        module_level = [n for n in dir(marketplace) if not n.startswith("_")]
        assert name not in module_level


# ── substitution rules ────────────────────────────────────────────────────────
class TestSubstitution:
    def test_a_whole_placeholder_keeps_the_value_type(self) -> None:
        body = dict(TEMPLATE_BODY)
        body["config"] = {"blast_radius": {"max_concurrent_faults": "{{ budget }}"}}
        template = _template(
            parameters=(
                TemplateParameter(name="experiment_name", description="name"),
                TemplateParameter(name="namespace", description="ns"),
                TemplateParameter(name="duration", description="dur"),
                TemplateParameter(name="budget", description="concurrent faults"),
            ),
            drill_template=body,
        )
        doc = render_template(template, {**VALUES, "budget": 3})
        budget = doc["config"]["blast_radius"]["max_concurrent_faults"]
        assert budget == 3 and isinstance(budget, int)

    def test_an_embedded_placeholder_is_interpolated_as_text(self) -> None:
        body = json_roundtrip(
            {
                "kind": "drill",
                "name": "run-{{ experiment_name }}-01",
                "execution": [{"sequential": ["checkout"]}],
            }
        )
        template = _template(
            parameters=(TemplateParameter(name="experiment_name", description="name"),),
            drill_template=body,
        )
        assert render_template(template, {"experiment_name": "checkout"})["name"] == (
            "run-checkout-01"
        )

    def test_a_default_fills_an_optional_slot_the_caller_omitted(self) -> None:
        template = _template(
            parameters=(
                TemplateParameter(name="experiment_name", description="name"),
                TemplateParameter(
                    name="duration", description="dur", required=False, default="10s"
                ),
            ),
            drill_template={
                "kind": "drill",
                "name": "{{ experiment_name }}",
                "hypothesis": "runs for {{ duration }}",
                "execution": [{"sequential": ["checkout"]}],
            },
        )
        doc = render_template(template, {"experiment_name": "x"})
        assert doc["hypothesis"] == "runs for 10s"

    def test_an_explicit_value_beats_the_default(self) -> None:
        template = _template(
            parameters=(
                TemplateParameter(name="experiment_name", description="name"),
                TemplateParameter(
                    name="duration", description="dur", required=False, default="10s"
                ),
            ),
            drill_template={
                "kind": "drill",
                "name": "{{ experiment_name }}",
                "hypothesis": "runs for {{ duration }}",
                "execution": [{"sequential": ["checkout"]}],
            },
        )
        doc = render_template(template, {"experiment_name": "x", "duration": "45s"})
        assert doc["hypothesis"] == "runs for 45s"

    def test_placeholders_are_found_at_any_depth(self) -> None:
        found = unfilled_placeholders(
            {"a": [{"b": "{{ deep }}"}, "{{ top }}"], "c": ("{{ tuple }}",)}
        )
        assert set(found) == {"deep", "top", "tuple"}

    def test_braces_that_are_not_a_placeholder_are_left_alone(self) -> None:
        # A JSON body inlined into a fault parameter contains braces and must not
        # be mistaken for a slot.
        body = json_roundtrip(
            {
                "kind": "drill",
                "name": "{{ name }}",
                "targets": {"checkout": {"params": '{"note": "not a {{ slot }}"}'}},
                "execution": [{"sequential": ["checkout"]}],
            }
        )
        template = _template(
            parameters=(
                TemplateParameter(name="name", description="n"),
                TemplateParameter(name="slot", description="s"),
            ),
            drill_template=body,
        )
        doc = render_template(template, {"name": "checkout", "slot": "filled"})
        assert doc["targets"]["checkout"]["params"] == '{"note": "not a filled"}'

    def test_placeholders_are_found_in_mapping_keys_too(self) -> None:
        assert unfilled_placeholders({"{{ slot }}": 1}) == ("slot",)

    def test_the_declared_parameters_are_reported_in_order(self) -> None:
        assert template_parameters(_template()) == (
            "experiment_name",
            "namespace",
            "duration",
        )


# ── refusals: every one named, and every one load-bearing ─────────────────────
class TestRefusals:
    def test_a_missing_required_parameter_is_refused_by_name(self) -> None:
        with pytest.raises(TemplateInstantiationError) as exc:
            render_template(_template(), {"experiment_name": "x", "namespace": "shop"})
        assert exc.value.rule == "template.missing_parameter"
        assert "duration" in str(exc.value)

    def test_an_undeclared_value_is_refused_rather_than_ignored(self) -> None:
        with pytest.raises(TemplateInstantiationError) as exc:
            render_template(_template(), {**VALUES, "nmaespace": "typo"})
        assert exc.value.rule == "template.unknown_parameter"
        assert "nmaespace" in str(exc.value)

    def test_a_value_outside_the_choices_is_refused(self) -> None:
        template = _template(
            parameters=(
                TemplateParameter(name="experiment_name", description="name"),
                TemplateParameter(name="namespace", description="ns", choices=("shop", "staging")),
                TemplateParameter(name="duration", description="dur"),
            )
        )
        with pytest.raises(TemplateInstantiationError) as exc:
            render_template(template, {**VALUES, "namespace": "prod"})
        assert exc.value.rule == "template.choice_not_allowed"

    def test_a_template_with_no_execution_block_is_refused(self) -> None:
        with pytest.raises(Exception) as exc:
            _template(drill_template={"kind": "drill", "name": "{{ experiment_name }}"})
        assert "execution" in str(exc.value)

    def test_an_empty_drill_template_is_refused(self) -> None:
        with pytest.raises(Exception) as exc:
            _template(drill_template={})
        assert "empty" in str(exc.value)

    def test_a_placeholder_nobody_declared_is_refused_at_publication(self) -> None:
        with pytest.raises(ArtifactDeclarationError) as exc:
            _template(parameters=(TemplateParameter(name="experiment_name", description="name"),))
        assert exc.value.rule == "template.undeclared_placeholder"
        assert "namespace" in str(exc.value)

    def test_a_repeated_parameter_is_refused_at_publication(self) -> None:
        with pytest.raises(ArtifactDeclarationError) as exc:
            _template(
                parameters=(
                    TemplateParameter(name="experiment_name", description="name"),
                    TemplateParameter(name="experiment_name", description="again"),
                )
            )
        assert exc.value.rule == "template.duplicate_parameter"

    def test_a_private_template_may_not_name_another_organization(self) -> None:
        with pytest.raises(ArtifactDeclarationError) as exc:
            _template(
                publisher=PublisherDeclaration(
                    publisher_id="other",
                    display_name="Other",
                    contact="x@other.test",
                    organization="other",
                )
            )
        assert exc.value.rule == "template.organization_mismatch"

    def test_a_bad_digest_is_refused(self) -> None:
        with pytest.raises(Exception) as exc:
            _template(digest="not-a-digest")
        assert "64 lowercase hex" in str(exc.value)

    def test_the_refusal_type_is_a_domain_error(self) -> None:
        assert issubclass(TemplateInstantiationError, DomainError)


class TestUnfilledPlaceholderIsTheLoadBearingControl:
    """The refusal that stops a half-rendered drill from compiling.

    ``ExperimentTemplate``'s publication check refuses a body using an
    *undeclared* placeholder, so in normal use the render-time leftover can only
    appear if that check is bypassed. It is bypassed here on purpose: the point
    is to prove the **second** gate bites on its own, rather than being a
    restatement of the first. Without it, a future edit that relaxed
    publication validation would silently turn every template into a
    half-rendering machine.
    """

    def _broken_template(self) -> ExperimentTemplate:
        return ExperimentTemplate.model_construct(
            template_id="checkout.pod_kill",
            version="1.0.0",
            digest=_digest(b"broken"),
            publisher=_publisher(),
            registry=_registry(),
            parameters=(),
            drill_template={
                "kind": "drill",
                "name": "{{ nobody_declared_this }}",
                "execution": [{"sequential": ["checkout"]}],
            },
            license_id="Apache-2.0",
            changelog_ref="CHANGELOG.md#1.0.0",
            deprecation=None,
        )

    def test_a_body_with_an_undeclared_slot_refuses_to_render(self) -> None:
        with pytest.raises(TemplateInstantiationError) as exc:
            render_template(self._broken_template(), {})
        assert exc.value.rule == "template.unfilled_placeholder"
        assert "nobody_declared_this" in str(exc.value)

    def test_supplying_an_undeclared_slot_is_refused_too(self) -> None:
        with pytest.raises(TemplateInstantiationError) as exc:
            render_template(self._broken_template(), {"nobody_declared_this": "x"})
        assert exc.value.rule == "template.unknown_parameter"

    def test_a_partially_filled_body_never_becomes_a_spec(self) -> None:
        # The control read end-to-end: the refusal is an error, not a document.
        # If the guard were removed, this returns a DrillSpec whose `name` is the
        # literal string "{{ nobody_declared_this }}".
        with pytest.raises(TemplateInstantiationError):
            instantiate_spec(self._broken_template(), {})

    def test_publication_refuses_an_undeclared_placeholder_normally(self) -> None:
        with pytest.raises(ArtifactDeclarationError) as exc:
            _template(parameters=(TemplateParameter(name="experiment_name", description="name"),))
        assert exc.value.rule == "template.undeclared_placeholder"


# ── honesty: a template carries no trust claim ────────────────────────────────
class TestTemplatesCarryNoTrustClaim:
    @pytest.mark.parametrize("field", ["class", "verified", "trusted", "trust_label", "signature"])
    def test_no_trust_field_exists_on_the_template(self, field: str) -> None:
        assert field not in ExperimentTemplate.model_fields

    def test_a_caller_cannot_pass_an_undeclared_field(self) -> None:
        with pytest.raises(Exception) as exc:
            _template(verified=True)  # type: ignore[call-arg]
        assert "verified" in str(exc.value)

    def test_signature_verification_is_still_not_implemented(self) -> None:
        assert marketplace.SIGNATURE_VERIFICATION_IMPLEMENTED is False

    @pytest.mark.parametrize("field", ["signature", "key_id", "algorithm", "public_key", "signer"])
    def test_the_publisher_carries_no_authentication_field(self, field: str) -> None:
        assert field not in PublisherDeclaration.model_fields

    def test_a_template_carrying_a_literal_credential_is_refused(self) -> None:
        # Plan 29's gate, which `parse_drill` applies to every authored document.
        # A template is an authored document that arrived by another route, so
        # without this call it would have been a second door into the domain that
        # skipped the scan.
        body = json_roundtrip(
            {
                "kind": "drill",
                "name": "{{ experiment_name }}",
                "targets": {
                    "checkout": {
                        "faults": [{"fault": "k8s.pod_kill", "password": "hunter2hunter2"}]
                    }
                },
                "execution": [{"sequential": ["checkout"]}],
            }
        )
        template = _template(
            parameters=(TemplateParameter(name="experiment_name", description="name"),),
            drill_template=body,
        )
        with pytest.raises(InvariantViolationError) as exc:
            instantiate_spec(template, {"experiment_name": "x"})
        assert "hunter2" not in str(exc.value)


def json_roundtrip(value: Any) -> Any:
    """A copy that is definitely not the same object the module was handed."""
    import json

    return json.loads(json.dumps(value))
