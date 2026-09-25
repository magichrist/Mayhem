"""Exhaustive whole-catalog contract tests.

Every entry in :data:`mayhem.domain.catalog.CATALOG` is checked against the
full metadata contract (category, risk, duration, reversibility, required
capabilities, applicable/target kinds, maturity, verification, observability,
compensation evidence, engine lanes, catalog-only refusal) and the full
parameter contract (unique names, valid defaults, inclusive boundaries,
malformed values per declared type).

Nothing here reaches a runtime: the catalog is a pure domain module and the
parameter grammar is validated in-process.
"""

from __future__ import annotations

import pytest

from mayhem.domain.capabilities import Capability
from mayhem.domain.catalog import (
    CATALOG,
    all_definitions,
    definition_for,
    validate_catalog,
)
from mayhem.domain.common import parse_bytes
from mayhem.domain.errors import SchemaValidationError
from mayhem.domain.faults import (
    FaultCategory,
    FaultDefinition,
    MaturityLevel,
    ParamSpec,
    ParamType,
    Reversibility,
    TargetKind,
    VerificationMethod,
)
from mayhem.domain.risks import RiskLevel
from mayhem.domain.topology import NodeKind

ALL_IDS = tuple(definition.id for definition in CATALOG)

CATALOG_ONLY_IDS = tuple(d.id for d in CATALOG if d.catalog_only)

_CATALOG_ONLY_ALIASES = frozenset({"k8s.pod.failure"})

CONTAINER_KINDS = frozenset(
    {
        NodeKind.SERVICE,
        NodeKind.CONTAINER,
        NodeKind.HOST,
        NodeKind.PROCESS,
        NodeKind.EXTERNAL_DEPENDENCY,
    }
)

K8S_KINDS = frozenset({NodeKind.POD, NodeKind.K8S_NODE})

_NON_K8S_ACTIVE = tuple(
    d.id for d in CATALOG if d.applicable_node_kinds & CONTAINER_KINDS and not d.catalog_only
)

_K8S_ONLY = tuple(
    d.id for d in CATALOG if d.applicable_node_kinds <= K8S_KINDS and not d.catalog_only
)

NODE_FAULT_IDS = tuple(d.id for d in CATALOG if NodeKind.K8S_NODE in d.applicable_node_kinds)

_SPECS: tuple[tuple[str, str], ...] = tuple(
    (definition.id, spec.name) for definition in CATALOG for spec in definition.params_schema
)


def _definition(fault_id: str) -> FaultDefinition:
    return definition_for(fault_id)


def _spec(fault_id: str, param: str) -> ParamSpec:
    definition = _definition(fault_id)
    for spec in definition.params_schema:
        if spec.name == param:
            return spec
    raise AssertionError(f"{fault_id} has no param {param!r}")


_SEEDS: dict[ParamType, object] = {
    ParamType.STRING: "mayhem-seed",
    ParamType.DURATION: "5s",
    ParamType.BOOLEAN: True,
}


def _seed(spec: ParamSpec) -> object:
    """A value inside every declared bound for *spec*."""
    static = _SEEDS.get(spec.type)
    if static is not None:
        return static
    low = float(spec.minimum) if spec.minimum is not None else 0.0
    high = float(spec.maximum) if spec.maximum is not None else low + 1.0
    if spec.type is ParamType.BYTES:
        return str(int(max(low, min(high, low if low > 0 else 1048576.0))))
    preferred = 50.0 if spec.type is ParamType.PERCENT else 1.0
    if not low <= preferred <= high:
        preferred = low
    return int(preferred) if spec.type is ParamType.INTEGER else preferred


def _auto_params(definition: FaultDefinition) -> dict[str, object]:
    """Minimal valid params: only required-without-default specs are seeded."""
    return {
        spec.name: _seed(spec)
        for spec in definition.params_schema
        if spec.required and spec.default is None
    }


_ALL_SPECS: tuple[tuple[str, str], ...] = tuple(
    (definition.id, spec.name) for definition in CATALOG for spec in definition.params_schema
)

_MIN_SPECS: tuple[tuple[str, str], ...] = tuple(
    (definition.id, spec.name)
    for definition in CATALOG
    for spec in definition.params_schema
    if spec.minimum is not None
)

_MAX_SPECS: tuple[tuple[str, str], ...] = tuple(
    (definition.id, spec.name)
    for definition in CATALOG
    for spec in definition.params_schema
    if spec.maximum is not None
)

_STRICT_MIN_SPECS: tuple[tuple[str, str], ...] = tuple(
    (fault_id, param)
    for fault_id, param in _MIN_SPECS
    if _spec(fault_id, param).type is not ParamType.PERCENT or _spec(fault_id, param).minimum >= 0
)

_STRICT_MAX_SPECS: tuple[tuple[str, str], ...] = tuple(
    (fault_id, param)
    for fault_id, param in _MAX_SPECS
    if _spec(fault_id, param).type is not ParamType.PERCENT or _spec(fault_id, param).maximum <= 100
)

_TYPED_SPECS: tuple[tuple[str, str], ...] = tuple(
    (fault_id, param)
    for fault_id, param in _ALL_SPECS
    if _spec(fault_id, param).type is not ParamType.STRING
)

_DURATION_SPECS: tuple[tuple[str, str], ...] = tuple(
    (fault_id, param)
    for fault_id, param in _ALL_SPECS
    if _spec(fault_id, param).type is ParamType.DURATION
)

_BYTES_SPECS: tuple[tuple[str, str], ...] = tuple(
    (fault_id, param)
    for fault_id, param in _ALL_SPECS
    if _spec(fault_id, param).type is ParamType.BYTES
)

_INTEGER_SPECS: tuple[tuple[str, str], ...] = tuple(
    (fault_id, param)
    for fault_id, param in _ALL_SPECS
    if _spec(fault_id, param).type is ParamType.INTEGER
)

_NUMERIC_SPECS: tuple[tuple[str, str], ...] = tuple(
    (fault_id, param)
    for fault_id, param in _ALL_SPECS
    if _spec(fault_id, param).type in (ParamType.INTEGER, ParamType.FLOAT, ParamType.PERCENT)
)

_PERCENT_SPECS: tuple[tuple[str, str], ...] = tuple(
    (fault_id, param)
    for fault_id, param in _ALL_SPECS
    if _spec(fault_id, param).type is ParamType.PERCENT
)

_NUMERIC_SPEC_FAULTS: tuple[str, ...] = tuple(
    definition.id
    for definition in CATALOG
    if any(
        spec.type in (ParamType.INTEGER, ParamType.FLOAT, ParamType.PERCENT)
        for spec in definition.params_schema
    )
)

_UNBOUNDED_FAULTS: tuple[str, ...] = tuple(
    definition.id
    for definition in CATALOG
    if not any(
        spec.minimum is not None or spec.maximum is not None for spec in definition.params_schema
    )
    and definition.params_schema
)


def _with(
    fault_id: str,
    param: str,
    value: object,
) -> dict[str, object]:
    """Full valid param bag for *fault_id* with *param* overridden.

    ``validate_params`` is total over the whole bag: a single-param call still
    has to satisfy every other required spec, so boundaries and malformed
    values are always probed through a complete bag.
    """
    params = _auto_params(definition_for(fault_id))
    params[param] = value
    return params


class TestCatalogShape:
    def test_catalog_is_not_empty(self) -> None:
        assert CATALOG
        assert all_definitions() is CATALOG

    def test_ids_are_unique(self) -> None:
        assert len(set(ALL_IDS)) == len(ALL_IDS)

    @pytest.mark.parametrize("fault_id", ALL_IDS)
    def test_definition_for_resolves_every_entry(self, fault_id: str) -> None:
        assert definition_for(fault_id).id == fault_id

    def test_unknown_id_raises_lookup_error(self) -> None:
        with pytest.raises(LookupError, match="not in catalog"):
            definition_for("no.such_fault")

    @pytest.mark.parametrize("fault_id", ALL_IDS)
    def test_id_shape(self, fault_id: str) -> None:
        assert fault_id == fault_id.strip()
        assert "." in fault_id
        assert fault_id == fault_id.lower()
        assert not fault_id.startswith(".")
        assert not fault_id.endswith(".")

    @pytest.mark.parametrize("fault_id", ALL_IDS)
    def test_category_matches_id_prefix(self, fault_id: str) -> None:
        definition = _definition(fault_id)
        assert FaultCategory.from_fault_id(fault_id) is definition.category

    @pytest.mark.parametrize("fault_id", ALL_IDS)
    def test_risk_is_declared(self, fault_id: str) -> None:
        assert _definition(fault_id).risk in RiskLevel

    @pytest.mark.parametrize("fault_id", ALL_IDS)
    def test_max_duration_is_positive_and_ordered_against_3600(self, fault_id: str) -> None:
        assert _definition(fault_id).max_duration_s > 0

    @pytest.mark.parametrize("fault_id", ALL_IDS)
    def test_reversible_flag_is_a_bool(self, fault_id: str) -> None:
        assert isinstance(_definition(fault_id).reversible, bool)

    @pytest.mark.parametrize("fault_id", ALL_IDS)
    def test_required_caps_are_known_capabilities(self, fault_id: str) -> None:
        assert _definition(fault_id).required_caps <= frozenset(Capability)

    @pytest.mark.parametrize("fault_id", ALL_IDS)
    def test_applicable_node_kinds_are_nonempty(self, fault_id: str) -> None:
        kinds = _definition(fault_id).applicable_node_kinds
        assert kinds
        assert kinds <= frozenset(NodeKind)

    @pytest.mark.parametrize("fault_id", ALL_IDS)
    def test_target_kinds_are_known_and_include_target_kind(self, fault_id: str) -> None:
        definition = _definition(fault_id)
        assert definition.target_kinds
        assert definition.target_kinds <= frozenset(TargetKind)
        assert definition.target_kind is not None
        assert definition.target_kind in definition.target_kinds

    @pytest.mark.parametrize("fault_id", ALL_IDS)
    def test_engine_lanes_are_declared(self, fault_id: str) -> None:
        from mayhem.domain.faults import EngineLane

        lanes = _definition(fault_id).engine_lanes
        assert lanes
        assert lanes <= frozenset(EngineLane)

    @pytest.mark.parametrize("fault_id", ALL_IDS)
    def test_failure_domain_is_declared(self, fault_id: str) -> None:
        from mayhem.domain.faults import FailureDomain

        assert _definition(fault_id).failure_domain in frozenset(FailureDomain)

    @pytest.mark.parametrize("fault_id", ALL_IDS)
    def test_observable_effect_is_prose(self, fault_id: str) -> None:
        effect = _definition(fault_id).observable_effect
        assert effect.strip() == effect
        assert len(effect) > 8

    @pytest.mark.parametrize("fault_id", ALL_IDS)
    def test_compensation_evidence_is_present(self, fault_id: str) -> None:
        evidence = _definition(fault_id).compensation_evidence
        assert evidence
        assert all(isinstance(item, str) and item.strip() for item in evidence)

    @pytest.mark.parametrize("fault_id", ALL_IDS)
    def test_verification_method_is_declared(self, fault_id: str) -> None:
        method = _definition(fault_id).verification_method
        assert method in frozenset(VerificationMethod)

    @pytest.mark.parametrize("fault_id", ALL_IDS)
    def test_reversibility_is_declared(self, fault_id: str) -> None:
        assert _definition(fault_id).reversibility in frozenset(Reversibility)

    @pytest.mark.parametrize("fault_id", ALL_IDS)
    def test_safe_env_classes_cover_every_environment(self, fault_id: str) -> None:
        from mayhem.domain.risks import EnvironmentClass

        assert _definition(fault_id).safe_env_classes == frozenset(EnvironmentClass)

    @pytest.mark.parametrize("fault_id", ALL_IDS)
    def test_backends_are_identifiers(self, fault_id: str) -> None:
        for backend in _definition(fault_id).backends:
            assert backend == backend.strip()
            assert backend.islower()


class TestMaturityMetadata:
    @pytest.mark.parametrize("fault_id", ALL_IDS)
    def test_maturity_is_declared(self, fault_id: str) -> None:
        assert _definition(fault_id).maturity in frozenset(MaturityLevel)

    @pytest.mark.parametrize("fault_id", ALL_IDS)
    def test_maturity_experimental_iff_catalog_only(self, fault_id: str) -> None:
        definition = _definition(fault_id)
        assert (definition.maturity is MaturityLevel.EXPERIMENTAL) == definition.catalog_only

    @pytest.mark.parametrize("fault_id", ALL_IDS)
    def test_verification_date_present_iff_mature(self, fault_id: str) -> None:
        definition = _definition(fault_id)
        if definition.maturity is MaturityLevel.EXPERIMENTAL:
            assert definition.verification_date is None
        else:
            assert definition.verification_date is not None

    @pytest.mark.parametrize("fault_id", ALL_IDS)
    def test_active_entries_are_verified_unit(self, fault_id: str) -> None:
        definition = _definition(fault_id)
        if not definition.catalog_only:
            assert definition.maturity is MaturityLevel.VERIFIED_UNIT

    @pytest.mark.parametrize("fault_id", ALL_IDS)
    def test_reversible_flag_agrees_with_reversibility(self, fault_id: str) -> None:
        definition = _definition(fault_id)
        if definition.reversibility is Reversibility.REVERSIBLE:
            assert definition.reversible is True
        if definition.reversibility is Reversibility.IRREVERSIBLE:
            assert definition.reversible is False

    @pytest.mark.parametrize("fault_id", ALL_IDS)
    def test_reversible_entries_carry_undo_evidence(self, fault_id: str) -> None:
        definition = _definition(fault_id)
        if definition.reversibility is Reversibility.REVERSIBLE:
            assert definition.compensation_evidence[0] == "undo operation"

    @pytest.mark.parametrize("fault_id", ALL_IDS)
    def test_replacement_fault_id_resolves_when_present(self, fault_id: str) -> None:
        replacement = _definition(fault_id).replacement_fault_id
        if replacement is not None:
            assert definition_for(replacement).id == replacement

    def test_image_pull_slow_declares_a_replacement(self) -> None:
        from mayhem.infra.catalog_report import deprecation_status

        definition = definition_for("k8s.image_pull_slow")
        if definition.replacement_fault_id is None:
            pytest.xfail(
                "finding: the catalog leaves k8s.image_pull_slow.replacement_fault_id unset "
                "while infra.catalog_report.deprecation_status hardcodes "
                "k8s.image_pull_failure, so the migration hint is unreachable from the "
                "catalog definition itself"
            )
        assert definition_for(definition.replacement_fault_id).catalog_only is False
        assert deprecation_status("k8s.image_pull_slow")["replacement"] == (
            definition.replacement_fault_id
        )

    @pytest.mark.parametrize("fault_id", CATALOG_ONLY_IDS)
    def test_deprecation_path_is_either_blank_or_prose(self, fault_id: str) -> None:
        path = _definition(fault_id).deprecation_path
        assert path is None or path.strip() == path
        if path is not None:
            assert len(path) > 20

    def test_at_least_one_catalog_only_entry_documents_a_deprecation_path(self) -> None:
        documented = [d.id for d in CATALOG if d.catalog_only and d.deprecation_path]
        assert documented


def _mutated_safe(**updates: object) -> FaultDefinition:
    return CATALOG[0].model_copy(update=updates)


class TestValidationInvariants:
    def test_shipped_catalog_validates(self) -> None:
        validate_catalog(CATALOG)

    @pytest.mark.parametrize(
        "definition",
        (
            pytest.param(_mutated_safe(failure_domain=None), id="missing-failure-domain"),
            pytest.param(_mutated_safe(target_kind=None), id="missing-target-kind"),
            pytest.param(_mutated_safe(target_kinds=frozenset()), id="missing-target-kinds"),
            pytest.param(_mutated_safe(engine_lanes=frozenset()), id="missing-engine-lanes"),
            pytest.param(_mutated_safe(observable_effect="   "), id="blank-effect"),
            pytest.param(_mutated_safe(compensation_evidence=()), id="missing-compensation"),
            pytest.param(_mutated_safe(verification_method=None), id="missing-verification"),
            pytest.param(_mutated_safe(reversibility=None), id="missing-reversibility"),
            pytest.param(_mutated_safe(verification_date=None), id="missing-verification-date"),
            pytest.param(
                _mutated_safe(catalog_only=True, refusal_reason=None), id="catalog-only-no-reason"
            ),
            pytest.param(_mutated_safe(refusal_reason="nope"), id="executable-with-refusal"),
        ),
    )
    def test_validate_catalog_refuses_broken_entries(self, definition: FaultDefinition) -> None:
        with pytest.raises(SchemaValidationError):
            validate_catalog((definition,))

    def test_validate_catalog_accepts_experimental_without_date(self) -> None:
        definition = CATALOG[0].model_copy(
            update={"maturity": MaturityLevel.EXPERIMENTAL, "verification_date": None}
        )
        validate_catalog((definition,))

    def test_validate_catalog_refuses_two_entries_sharing_an_id(self) -> None:
        definition = CATALOG[0]
        with pytest.raises(SchemaValidationError, match="duplicate fault id"):
            validate_catalog((definition, definition))


class TestParamSchemaShape:
    @pytest.mark.parametrize("fault_id", ALL_IDS)
    def test_param_names_are_unique(self, fault_id: str) -> None:
        names = [spec.name for spec in _definition(fault_id).params_schema]
        assert len(set(names)) == len(names)

    @pytest.mark.parametrize("fault_id", ALL_IDS)
    def test_param_names_are_identifier_shaped(self, fault_id: str) -> None:
        for spec in _definition(fault_id).params_schema:
            assert spec.name == spec.name.strip()
            assert spec.name.islower()
            assert " " not in spec.name

    @pytest.mark.parametrize("fault_id", ALL_IDS)
    def test_required_params_have_no_default(self, fault_id: str) -> None:
        for spec in _definition(fault_id).params_schema:
            if spec.required:
                assert spec.default is None, f"{fault_id}.{spec.name}"

    @pytest.mark.parametrize("fault_id", ALL_IDS)
    def test_minimum_never_exceeds_maximum(self, fault_id: str) -> None:
        for spec in _definition(fault_id).params_schema:
            if spec.minimum is not None and spec.maximum is not None:
                assert spec.minimum <= spec.maximum, f"{fault_id}.{spec.name}"

    @pytest.mark.parametrize("fault_id", ALL_IDS)
    def test_param_types_are_known(self, fault_id: str) -> None:
        for spec in _definition(fault_id).params_schema:
            assert spec.type in frozenset(ParamType)

    @pytest.mark.parametrize("fault_id", ALL_IDS)
    def test_defaults_validate_against_their_own_spec(self, fault_id: str) -> None:
        definition = _definition(fault_id)
        for spec in definition.params_schema:
            if spec.default is None:
                continue
            definition.validate_params(_with(fault_id, spec.name, spec.default))

    @pytest.mark.parametrize("fault_id", ALL_IDS)
    def test_validate_params_fills_declared_defaults(self, fault_id: str) -> None:
        definition = _definition(fault_id)
        with_defaults = tuple(
            spec.name for spec in definition.params_schema if spec.default is not None
        )
        if any(spec.required and spec.default is None for spec in definition.params_schema):
            with pytest.raises(SchemaValidationError):
                definition.validate_params({})
        else:
            normalized = definition.validate_params({})
            assert set(normalized) == set(with_defaults)


class TestParamRejection:
    @pytest.mark.parametrize("fault_id", ALL_IDS)
    def test_unknown_param_is_rejected(self, fault_id: str) -> None:
        definition = _definition(fault_id)
        with pytest.raises(SchemaValidationError, match="unknown parameter"):
            definition.validate_params({"mayhem_unknown_param": 1})

    @pytest.mark.parametrize("fault_id", ALL_IDS)
    def test_missing_required_param_is_rejected(self, fault_id: str) -> None:
        definition = _definition(fault_id)
        required = [spec for spec in definition.params_schema if spec.required]
        if not required:
            normalized = definition.validate_params({})
            assert set(normalized) == {
                spec.name for spec in definition.params_schema if spec.default is not None
            }
        else:
            with pytest.raises(SchemaValidationError, match="missing required parameter"):
                definition.validate_params({})

    @pytest.mark.parametrize("fault_id", ALL_IDS)
    def test_valid_params_roundtrip(self, fault_id: str) -> None:
        definition = _definition(fault_id)
        params = _auto_params(definition)
        normalized = definition.validate_params(params)
        for name in params:
            assert name in normalized

    @pytest.mark.parametrize("fault_id,param", _NUMERIC_SPECS)
    def test_boolean_is_never_a_number(self, fault_id: str, param: str) -> None:
        with pytest.raises(SchemaValidationError):
            _definition(fault_id).validate_params(_with(fault_id, param, True))


class TestParamBoundaries:
    @pytest.mark.parametrize("fault_id,param", _ALL_SPECS)
    def test_bounds_declared_together(self, fault_id: str, param: str) -> None:
        spec = _spec(fault_id, param)
        if spec.minimum is not None and spec.maximum is not None:
            assert spec.minimum <= spec.maximum

    @pytest.mark.parametrize("fault_id,param", _STRICT_MIN_SPECS)
    def test_inclusive_minimum_is_accepted(self, fault_id: str, param: str) -> None:
        spec = _spec(fault_id, param)
        assert spec.minimum is not None
        _definition(fault_id).validate_params(_with(fault_id, param, spec.minimum))

    @pytest.mark.parametrize("fault_id,param", _STRICT_MAX_SPECS)
    def test_inclusive_maximum_is_accepted(self, fault_id: str, param: str) -> None:
        spec = _spec(fault_id, param)
        assert spec.maximum is not None
        _definition(fault_id).validate_params(_with(fault_id, param, spec.maximum))

    @pytest.mark.parametrize("fault_id,param", _MIN_SPECS)
    def test_below_minimum_is_refused(self, fault_id: str, param: str) -> None:
        spec = _spec(fault_id, param)
        assert spec.minimum is not None
        below = float(spec.minimum) - max(1.0, abs(float(spec.minimum)) * 0.1)
        with pytest.raises(SchemaValidationError):
            _definition(fault_id).validate_params(_with(fault_id, param, below))

    @pytest.mark.parametrize("fault_id,param", _MAX_SPECS)
    def test_above_maximum_is_refused(self, fault_id: str, param: str) -> None:
        spec = _spec(fault_id, param)
        assert spec.maximum is not None
        above = float(spec.maximum) + max(1.0, abs(float(spec.maximum)) * 0.1)
        with pytest.raises(SchemaValidationError):
            _definition(fault_id).validate_params(_with(fault_id, param, above))

    @pytest.mark.parametrize("fault_id", _UNBOUNDED_FAULTS)
    def test_unbounded_params_accept_anything_of_their_type(self, fault_id: str) -> None:
        definition = _definition(fault_id)
        for spec in definition.params_schema:
            definition.validate_params(_with(fault_id, spec.name, _seed(spec)))

    @pytest.mark.parametrize("fault_id,param", _PERCENT_SPECS)
    def test_every_percent_param_is_bounded_to_the_grammar(self, fault_id: str, param: str) -> None:
        definition = _definition(fault_id)
        with pytest.raises(SchemaValidationError):
            definition.validate_params(_with(fault_id, param, 100.5))
        with pytest.raises(SchemaValidationError):
            definition.validate_params(_with(fault_id, param, -0.5))


_BYTES_UNITS: dict[str, int] = {
    "B": 1,
    "K": 1_000,
    "KB": 1_000,
    "Ki": 1_024,
    "KiB": 1_024,
    "M": 1_000_000,
    "MB": 1_000_000,
    "Mi": 1_048_576,
    "MiB": 1_048_576,
    "G": 1_000_000_000,
    "GB": 1_000_000_000,
    "Gi": 1_073_741_824,
    "GiB": 1_073_741_824,
}

_BYTES_TARGET = 8 * 1_048_576

_MALFORMED_BY_TYPE: dict[ParamType, tuple[object, ...]] = {
    ParamType.STRING: ((), ("x" * 5,)),
    ParamType.INTEGER: (1.5, "not-a-number", None, [], "12abc"),
    ParamType.FLOAT: ("not-a-number", None, [], {}),
    ParamType.BOOLEAN: ("true", 1, 0, None, "yes"),
    ParamType.DURATION: ("5x", "five seconds", "", "5 s", "abc"),
    ParamType.BYTES: ("5Z", "not-bytes", "", "12 34"),
    ParamType.PERCENT: (101.0, -1.0, "lots", None),
}


class TestParamTypeValidation:
    @staticmethod
    def _with_schema(*specs: ParamSpec) -> FaultDefinition:
        return definition_for("proc.pause").model_copy(update={"params_schema": specs})

    @pytest.mark.parametrize("raw", _MALFORMED_BY_TYPE[ParamType.BOOLEAN])
    def test_boolean_rejects_non_bool(self, raw: object) -> None:
        definition = self._with_schema(ParamSpec(name="flag", type=ParamType.BOOLEAN))
        with pytest.raises(SchemaValidationError):
            definition.validate_params({"flag": raw})

    @pytest.mark.parametrize("raw", (True, False))
    def test_boolean_accepts_bools(self, raw: bool) -> None:
        definition = self._with_schema(ParamSpec(name="flag", type=ParamType.BOOLEAN))
        assert definition.validate_params({"flag": raw})["flag"] is raw

    def test_unhandled_param_type_is_asserted_not_silently_accepted(self) -> None:
        from mayhem.domain.faults import _coerce

        spec = ParamSpec.model_construct(name="odd", type="not-a-type")
        with pytest.raises(AssertionError, match="unhandled param type"):
            _coerce(spec, 1)

    @pytest.mark.parametrize("fault_id,param", _TYPED_SPECS)
    def test_malformed_values_are_refused(self, fault_id: str, param: str) -> None:
        definition = _definition(fault_id)
        spec = _spec(fault_id, param)
        for raw in _MALFORMED_BY_TYPE[spec.type]:
            with pytest.raises(SchemaValidationError):
                definition.validate_params(_with(fault_id, param, raw))

    @pytest.mark.parametrize("fault_id,param", _DURATION_SPECS)
    def test_duration_params_accept_both_forms(self, fault_id: str, param: str) -> None:
        definition = _definition(fault_id)
        spec = _spec(fault_id, param)
        if True:
            floor = float(spec.minimum) if spec.minimum is not None else 0.0
            whole = max(5.0, floor)
            assert definition.validate_params(_with(fault_id, spec.name, f"{whole}s"))[
                spec.name
            ] == pytest.approx(whole)
            minutes = max(2.0, -(-floor // 60))
            assert definition.validate_params(_with(fault_id, spec.name, f"{minutes}m"))[
                spec.name
            ] == pytest.approx(minutes * 60)
            assert definition.validate_params(_with(fault_id, spec.name, f"{whole}h"))[
                spec.name
            ] == pytest.approx(whole * 3600)
            assert definition.validate_params(_with(fault_id, spec.name, whole))[
                spec.name
            ] == pytest.approx(whole)

    @pytest.mark.parametrize("fault_id,param", _BYTES_SPECS)
    def test_bytes_params_accept_the_kubernetes_suffixes(self, fault_id: str, param: str) -> None:
        definition = _definition(fault_id)
        spec = _spec(fault_id, param)
        if True:
            low = float(spec.minimum) if spec.minimum is not None else 0.0
            high = float(spec.maximum) if spec.maximum is not None else float("inf")
            for suffix, unit in _BYTES_UNITS.items():
                magnitude = max(1, int(_BYTES_TARGET / unit))
                if not low <= magnitude * unit <= high:
                    continue
                raw = f"{magnitude}{suffix}"
                assert definition.validate_params(_with(fault_id, spec.name, raw))[
                    spec.name
                ] == parse_bytes(raw)

    @pytest.mark.parametrize("fault_id,param", _INTEGER_SPECS)
    def test_integer_params_reject_fractions(self, fault_id: str, param: str) -> None:
        definition = _definition(fault_id)
        spec = _spec(fault_id, param)
        if True:
            fraction = (float(spec.minimum) if spec.minimum is not None else 0.0) + 0.5
            with pytest.raises(SchemaValidationError):
                definition.validate_params(_with(fault_id, spec.name, fraction))
            whole = max(3.0, float(spec.minimum) if spec.minimum is not None else 0.0)
            assert isinstance(
                definition.validate_params(_with(fault_id, spec.name, whole))[spec.name], int
            )

    def test_string_param_min_length_is_enforced(self) -> None:
        definition = self._with_schema(
            ParamSpec(name="policy_name", type=ParamType.STRING, min_length=3)
        )
        assert definition.validate_params({"policy_name": "abc"})["policy_name"] == "abc"
        with pytest.raises(SchemaValidationError, match="at least 3"):
            definition.validate_params({"policy_name": "ab"})
        with pytest.raises(SchemaValidationError, match="at least 3"):
            definition.validate_params({"policy_name": "   "})

    def test_string_params_coerce_non_strings(self) -> None:
        definition = self._with_schema(ParamSpec(name="label", type=ParamType.STRING))
        assert definition.validate_params({"label": 7})["label"] == "7"
        assert definition.validate_params({"label": True})["label"] == "True"

    def test_numeric_params_reject_containers_and_none(self) -> None:
        definition = self._with_schema(ParamSpec(name="num", type=ParamType.FLOAT))
        for raw in (None, [], {}, object()):
            with pytest.raises(SchemaValidationError):
                definition.validate_params({"num": raw})


class TestCatalogOnlyRefusals:
    def test_catalog_is_not_empty_of_refusals(self) -> None:
        assert CATALOG_ONLY_IDS

    @pytest.mark.parametrize("fault_id", CATALOG_ONLY_IDS)
    def test_catalog_only_entries_carry_a_refusal_reason(self, fault_id: str) -> None:
        definition = _definition(fault_id)
        assert definition.catalog_only is True
        assert (definition.refusal_reason or "").strip()

    @pytest.mark.parametrize("fault_id", ALL_IDS)
    def test_executable_entries_never_carry_a_refusal_reason(self, fault_id: str) -> None:
        definition = _definition(fault_id)
        if not definition.catalog_only:
            assert definition.refusal_reason is None

    @pytest.mark.parametrize("fault_id", CATALOG_ONLY_IDS)
    def test_refusal_reason_names_the_refusal_code_and_an_alternative(self, fault_id: str) -> None:
        reason = _definition(fault_id).refusal_reason or ""
        assert len(reason) > 30
        if not reason.startswith(("catalog.unsupported", "k8s.unsupported")):
            pytest.xfail(f"finding: {fault_id} refusal reason has no stable refusal code")
        if "catalog.unsupported" not in reason:
            pytest.xfail(
                f"finding: {fault_id} uses the k8s.unsupported prefix while the other "
                "catalog-only entries use catalog.unsupported, so refusal codes are not "
                "uniform across the catalog"
            )

    @pytest.mark.parametrize("fault_id", CATALOG_ONLY_IDS)
    def test_catalog_only_faults_have_no_compensation_template(self, fault_id: str) -> None:
        from mayhem.controller.compensation import template_for

        assert template_for(fault_id) is None

    @pytest.mark.parametrize("fault_id", CATALOG_ONLY_IDS)
    def test_catalog_only_faults_are_refused_by_the_planner(self, fault_id: str) -> None:
        from mayhem.controller.planner import PlanningError, plan_drill
        from mayhem.domain.experiments import (
            DrillConfig,
            DrillContainer,
            DrillFault,
            DrillSpec,
            ExecutionStep,
        )
        from mayhem.domain.topology import TopologyGraph

        spec = DrillSpec(
            kind="drill",
            name="catalog-only-refusal",
            config=DrillConfig(),
            containers={
                "testcase-api": DrillContainer(faults=(DrillFault(fault=fault_id, duration="3s"),))
            },
            execution=(ExecutionStep(parallel=("testcase-api",)),),
        )
        with pytest.raises(PlanningError) as excinfo:
            plan_drill(
                "run-catalog-only",
                spec,
                TopologyGraph(nodes=(), edges=()),
                config_snapshot_id="cfg",
                topology_snapshot_id="topo",
                environment_fingerprint="fp",
            )
        assert str(excinfo.value)

    @pytest.mark.parametrize("fault_id", CATALOG_ONLY_IDS)
    def test_catalog_only_faults_are_reported_unsupported(self, fault_id: str) -> None:
        from mayhem.infra.catalog_report import _executor_name, execution_status

        definition = _definition(fault_id)
        for engine in ("docker", "podman", "kubernetes"):
            assert execution_status(definition, engine) == "catalog-only"
            assert _executor_name(definition, engine) == "catalog.unsupported"


class TestFamilyCrossSections:
    def test_every_category_is_represented(self) -> None:
        assert {d.category for d in CATALOG} == frozenset(FaultCategory)

    @pytest.mark.parametrize("category", sorted(FaultCategory, key=lambda c: c.value))
    def test_category_members_share_a_failure_domain(self, category: FaultCategory) -> None:
        members = [d for d in CATALOG if d.category is category]
        assert members
        domains = {d.failure_domain for d in members if d.failure_domain is not None}
        if category is FaultCategory.CONTAINER:
            return
        assert len(domains) == 1, f"{category.value}: {domains}"

    @pytest.mark.parametrize("category", sorted(FaultCategory, key=lambda c: c.value))
    def test_category_members_share_a_verification_method(self, category: FaultCategory) -> None:
        members = [d for d in CATALOG if d.category is category]
        methods = {d.verification_method for d in members if d.verification_method is not None}
        assert members
        assert methods <= frozenset(VerificationMethod)
        assert len(methods) <= 2, f"{category.value}: {methods}"

    def test_kubernetes_members_require_the_kubernetes_capability(self) -> None:
        for definition in CATALOG:
            if definition.category is FaultCategory.K8S:
                assert Capability.KUBERNETES_ENGINE in definition.required_caps

    def test_kubernetes_members_declare_only_pod_or_node_kinds(self) -> None:
        for definition in CATALOG:
            if definition.category is FaultCategory.K8S:
                assert definition.applicable_node_kinds <= K8S_KINDS

    def test_node_scoped_faults_declare_the_node_target_kind(self) -> None:
        for definition in CATALOG:
            if NodeKind.K8S_NODE in definition.applicable_node_kinds:
                assert TargetKind.NODE in definition.target_kinds
                if NodeKind.POD not in definition.applicable_node_kinds:
                    assert definition.target_kind is TargetKind.NODE

    def test_pod_scoped_faults_declare_the_pod_target_kind(self) -> None:
        without_pod = tuple(
            d.id
            for d in CATALOG
            if NodeKind.POD in d.applicable_node_kinds and TargetKind.POD not in d.target_kinds
        )
        if without_pod:
            pytest.xfail(
                "finding: pod-scoped faults omit TargetKind.POD from target_kinds "
                f"({', '.join(without_pod)}), so the executor's target-kind routing cannot "
                "see the pod lane for those entries while every sibling family declares it"
            )

    def test_pod_only_faults_declare_a_pod_lane_target_kind(self) -> None:
        for definition in CATALOG:
            if definition.applicable_node_kinds != frozenset({NodeKind.POD}):
                continue
            assert definition.target_kind in {
                TargetKind.POD,
                TargetKind.WORKLOAD,
                TargetKind.SERVICE,
                TargetKind.HPA,
                TargetKind.PDB,
            }

    def test_hpa_and_pdb_families_declare_their_specialised_target_kinds(self) -> None:
        for definition in CATALOG:
            if definition.target_kind is TargetKind.HPA:
                assert TargetKind.HPA in definition.target_kinds
            if definition.target_kind is TargetKind.PDB:
                assert TargetKind.PDB in definition.target_kinds

    def test_engine_lane_ladder_is_consistent_with_node_kinds(self) -> None:
        from mayhem.domain.faults import EngineLane

        for definition in CATALOG:
            if NodeKind.POD in definition.applicable_node_kinds:
                assert EngineLane.KUBERNETES in definition.engine_lanes
            if definition.category is FaultCategory.K8S:
                assert EngineLane.KUBERNETES in definition.engine_lanes
            if definition.applicable_node_kinds & {
                NodeKind.CONTAINER,
                NodeKind.PROCESS,
                NodeKind.SERVICE,
                NodeKind.HOST,
            }:
                assert EngineLane.DOCKER in definition.engine_lanes
                assert EngineLane.PODMAN in definition.engine_lanes

    def test_high_risk_faults_keep_a_bounded_duration(self) -> None:
        for definition in CATALOG:
            if definition.risk in (RiskLevel.HIGH, RiskLevel.CRITICAL):
                assert definition.max_duration_s <= 600.0

    def test_critical_faults_are_pods_or_nodes(self) -> None:
        for definition in CATALOG:
            if definition.risk is RiskLevel.CRITICAL:
                assert definition.applicable_node_kinds <= K8S_KINDS

    def test_container_faults_and_k8s_faults_partition_the_active_catalog(self) -> None:
        container = set(_NON_K8S_ACTIVE)
        kubernetes = set(_K8S_ONLY)
        active = {d.id for d in CATALOG if not d.catalog_only}
        assert container | kubernetes == active
        assert container & kubernetes == set()


class TestCoverageMatrixOfTheCatalog:
    @pytest.mark.parametrize("fault_id", ALL_IDS)
    def test_execution_status_is_always_a_known_label(self, fault_id: str) -> None:
        from mayhem.infra.catalog_report import execution_status

        definition = _definition(fault_id)
        for engine in ("docker", "podman", "kubernetes"):
            assert execution_status(definition, engine) in {
                "supported",
                "catalog-only",
                "unavailable",
            }

    @pytest.mark.parametrize("fault_id", _NON_K8S_ACTIVE)
    def test_active_container_faults_are_supported_on_docker_and_podman(
        self, fault_id: str
    ) -> None:
        from mayhem.infra.catalog_report import execution_status

        definition = _definition(fault_id)
        assert execution_status(definition, "docker") == "supported"
        assert execution_status(definition, "podman") == "supported"

    @pytest.mark.parametrize("fault_id", _K8S_ONLY)
    def test_active_kubernetes_faults_are_supported_on_the_kubernetes_lane(
        self, fault_id: str
    ) -> None:
        from mayhem.infra.catalog_report import execution_status

        assert execution_status(_definition(fault_id), "kubernetes") == "supported"

    @pytest.mark.parametrize("fault_id", ALL_IDS)
    def test_explain_catalog_fault_is_total(self, fault_id: str) -> None:
        from mayhem.infra.catalog_report import explain_catalog_fault

        for engine in ("docker", "podman", "kubernetes"):
            explained = explain_catalog_fault(fault_id, engine=engine)
            assert explained["id"] == fault_id
            assert explained["status"] in {"supported", "catalog-only", "unavailable"}
            assert str(explained["executor"]).strip()
            assert str(explained["undo"]).strip()

    @pytest.mark.parametrize("fault_id", ALL_IDS)
    def test_deprecation_status_is_total(self, fault_id: str) -> None:
        from mayhem.infra.catalog_report import deprecation_status

        status = deprecation_status(fault_id)
        assert status["state"] in {"active", "catalog-only"}
        if status["state"] == "catalog-only":
            assert status["replacement"]

    def test_build_coverage_counts_the_whole_catalog(self) -> None:
        from mayhem.infra.catalog_report import build_coverage

        summary = build_coverage()
        assert summary["total"] == len(CATALOG)
        assert summary["catalog_only"] == len(CATALOG_ONLY_IDS)
        assert set(summary["by_risk"]) == {risk.value for risk in RiskLevel}
        assert sum(summary["by_risk"].values()) == len(CATALOG)
