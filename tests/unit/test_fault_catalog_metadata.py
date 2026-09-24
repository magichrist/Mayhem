from __future__ import annotations

from datetime import date

import pytest

from mayhem.domain.catalog import CATALOG, validate_catalog
from mayhem.domain.errors import SchemaValidationError
from mayhem.domain.faults import MaturityLevel
from mayhem.domain.target_profiles import TargetProfile
from mayhem.infra.catalog_report import (
    build_coverage,
    deprecation_status,
    explain_catalog_fault,
    recommend_faults,
)

REQUESTED_FAMILIES = frozenset(
    {
        "http.latency",
        "http.error_injection",
        "dependency.rate_limit",
        "net.connection_reset",
        "net.latency",
        "net.packet_loss",
        "net.duplicate",
        "net.reorder",
        "net.partition",
        "net.bandwidth",
        "fs.read_only",
        "fs.inode_exhaust",
        "fs.io_stress",
        "fs.permission_failure",
        "proc.pause",
        "process.stop",
        "process.kill",
        "process.crash_loop",
        "process.startup_delay",
        "dns.timeout",
        "dependency.timeout",
        "dependency.connection_refuse",
        "dependency.malformed_response",
    }
)


def test_catalog_metadata_contract_is_complete() -> None:
    validate_catalog(CATALOG)
    for definition in CATALOG:
        assert definition.failure_domain is not None
        assert definition.target_kind is not None
        assert definition.engine_lanes
        assert definition.observable_effect.strip()
        assert definition.verification_method is not None
        assert definition.maturity in MaturityLevel
        assert definition.reversibility is not None
        if definition.catalog_only:
            assert definition.refusal_reason
        else:
            assert definition.refusal_reason is None


def test_catalog_validation_rejects_incomplete_definition() -> None:
    incomplete = CATALOG[0].model_copy(update={"observable_effect": ""})
    with pytest.raises(SchemaValidationError, match="observable_effect"):
        validate_catalog((incomplete,))


def test_catalog_validation_rejects_duplicate_ids() -> None:
    with pytest.raises(SchemaValidationError, match="duplicate fault id"):
        validate_catalog((CATALOG[0], CATALOG[0]))


def test_verified_maturity_requires_verification_date() -> None:
    definition = CATALOG[0].model_copy(
        update={"maturity": MaturityLevel.VERIFIED_UNIT, "verification_date": None}
    )
    with pytest.raises(SchemaValidationError, match="verification_date"):
        validate_catalog((definition,))


def test_experimental_entries_do_not_claim_verification() -> None:
    for definition in CATALOG:
        if definition.maturity is MaturityLevel.EXPERIMENTAL:
            assert definition.verification_date is None
        else:
            assert isinstance(definition.verification_date, date)


def test_requested_reliability_families_are_present_and_explained() -> None:
    ids = {definition.id for definition in CATALOG}
    assert ids >= REQUESTED_FAMILIES
    for fault_id in REQUESTED_FAMILIES:
        explanation = explain_catalog_fault(fault_id, engine="docker")
        assert explanation["id"] == fault_id
        assert explanation["observable_effect"]
        assert explanation["verification_method"]
        assert explanation["status"] in {"supported", "catalog-only", "unavailable"}
        if explanation["status"] == "catalog-only":
            assert explanation["executor"] == "catalog.unsupported"


def test_coverage_is_generated_by_engine_domain_risk_and_reversibility() -> None:
    coverage = build_coverage()
    assert coverage["total"] == len(CATALOG)
    assert sum(coverage["by_engine"].values()) >= coverage["total"]
    assert sum(coverage["by_domain"].values()) == coverage["total"]
    assert sum(coverage["by_risk"].values()) == coverage["total"]
    assert sum(coverage["by_reversibility"].values()) == coverage["total"]
    assert coverage["catalog_only"] >= 3


def test_recommendations_respect_target_profile_engine_and_goal() -> None:
    profile = TargetProfile(name="local", engine="podman")
    recommendations = recommend_faults(profile, goal="network-resilience")
    assert recommendations
    assert recommendations[0].fault_id == "net.packet_loss"
    assert all(item.engine == "podman" for item in recommendations)
    assert all(item.status == "supported" for item in recommendations)


def test_platform_specific_catalog_entry_has_deprecation_path() -> None:
    status = deprecation_status("k8s.image_pull_slow")
    assert status["state"] == "catalog-only"
    assert status["replacement"]
    assert status["migration"]
