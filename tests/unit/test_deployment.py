"""Enterprise network policy, execution-mode markers, and feature flags
(docs/v1.1.0/20_ENTERPRISE_PRODUCT_HARDENING.md, Phase 1).

Five properties are defended here, and each has at least one test that would
fail if the property stopped holding:

1. **A network policy fails closed with a named cause.** ``egress_decision`` is
   total: an air-gapped install denies every host and says *why*, and a policy
   that says both "no egress" and "here is my allowlist" is refused outright
   rather than resolved by picking a winner. A test asserts the contradiction is
   refused, because an air-gapped install that quietly allows egress is the
   failure this type exists to make impossible.
2. **A demo-mode run cannot be presented as a production run.** The marker is
   *derived*, never supplied: ``sealed_mode_marker`` computes the banner and the
   ``mutates`` flag from the mode, and ``ModeMarker`` is frozen. So there is no
   construction path that yields a training marker claiming mutation, and the
   negative-control test asserts the presentation refusal for every non-production
   mode.
3. **Flag drift cannot reclassify sealed evidence.** ``flag_drift_refusal``
   compares the *requested* mode against the mode sealed into the marker. The
   test toggles what a flag would change and shows the sealed marker does not
   move — the run is classified by how it ran, not by how it is configured now.
4. **A feature flag may not be a backdoor.** A flag declaring that it affects
   execution mode or evidence presentation is refused by name, and
   ``resolve_flags`` refuses to enable a demo-only flag inside a production run.
5. **The refusals name themselves.** Every refusal starts with a stable rule id
   and the assertions below are on the id, not on prose. A rewording that keeps
   the meaning keeps passing; a check that loses its rule id fails.
"""

from __future__ import annotations

import pytest

from mayhem.domain.deployment import (
    DEMO_MODES,
    FEATURE_FLAGS,
    NO_MUTATION_PHRASE,
    SANDBOX_COMPONENTS,
    SANDBOX_DEPLOYMENT_MODEL,
    DeploymentModel,
    ExecutionMode,
    FeatureFlag,
    ModeClaim,
    NetworkPolicy,
    air_gap_refusal,
    deployment_profile,
    egress_decision,
    feature_flag,
    feature_flags_for,
    flag_drift_refusal,
    is_valid_network_policy,
    network_policy_problems,
    production_presentation_refusal,
    require_valid_network_policy,
    resolve_flags,
    sealed_mode_marker,
    validate_feature_flag,
    validate_network_policy,
)
from mayhem.domain.errors import InvariantViolationError

#: The full gap-77 vocabulary, declared as an operator would.
ENTERPRISE_POLICY = NetworkPolicy(
    http_proxy="http://proxy.corp.example:3128",
    https_proxy="http://proxy.corp.example:3128",
    custom_ca_bundle="/etc/mayhem/corp-ca.pem",
    private_registry="registry.corp.example",
    private_git="git@git.corp.example:platform.git",
    allowlist_enforced=True,
    outbound_allowlist=frozenset({"registry.corp.example", "git.corp.example"}),
)


def claim_for(mode: ExecutionMode, run_id: str = "run-1", **kwargs: object) -> ModeClaim:
    """A sealed claim in ``mode``, with sensible defaults for the rest."""
    return ModeClaim(
        run_id=run_id,
        marker=sealed_mode_marker(mode, basis="plan 20 test"),
        deployment_model=DeploymentModel.LOCAL,
        **kwargs,  # type: ignore[arg-type]
    )


# -- network policy -------------------------------------------------------------


def test_a_fully_declared_enterprise_policy_is_admissible() -> None:
    assert is_valid_network_policy(ENTERPRISE_POLICY)
    assert validate_network_policy(ENTERPRISE_POLICY) == ""
    assert network_policy_problems(ENTERPRISE_POLICY) == ()
    require_valid_network_policy(ENTERPRISE_POLICY)  # does not raise


def test_an_air_gapped_policy_with_an_outbound_allowlist_is_refused() -> None:
    """The contradiction the plan names: no egress *and* a list of reachable hosts."""
    policy = NetworkPolicy(
        air_gapped=True,
        allowlist_enforced=True,
        outbound_allowlist=frozenset({"updates.internal"}),
    )

    reason = validate_network_policy(policy)

    assert reason.startswith("network_policy.air_gapped_with_allowlist")
    assert "updates.internal" in reason
    assert not is_valid_network_policy(policy)
    with pytest.raises(InvariantViolationError) as caught:
        require_valid_network_policy(policy)
    assert caught.value.rule == "network_policy.air_gapped_with_allowlist"


def test_an_air_gapped_policy_without_an_allowlist_is_admissible() -> None:
    assert is_valid_network_policy(NetworkPolicy(air_gapped=True))


def test_a_wildcard_allowlist_entry_is_refused_because_it_is_not_a_policy() -> None:
    policy = NetworkPolicy(allowlist_enforced=True, outbound_allowlist=frozenset({"*"}))

    reason = validate_network_policy(policy)

    assert reason.startswith("network_policy.wildcard_allowlist")
    assert "absent policy" in reason


def test_a_leftmost_label_wildcard_is_a_real_policy_and_is_admitted() -> None:
    policy = NetworkPolicy(
        allowlist_enforced=True, outbound_allowlist=frozenset({"*.corp.example"})
    )

    assert is_valid_network_policy(policy)
    assert egress_decision(policy, "registry.corp.example").allowed
    assert egress_decision(policy, "corp.example").denied


@pytest.mark.parametrize(
    "entry",
    ["", " internal", "https://internal", "internal/path", "*internal", "[::1]", "a:b:c"],
)
def test_malformed_allowlist_entries_are_refused(entry: str) -> None:
    policy = NetworkPolicy(allowlist_enforced=True, outbound_allowlist=frozenset({entry}))

    reason = validate_network_policy(policy)

    assert reason.startswith("network_policy.malformed_allowlist_entry")


def test_every_problem_is_reported_not_only_the_first() -> None:
    policy = NetworkPolicy(
        air_gapped=True,
        http_proxy="proxy.corp.example:3128",
        outbound_allowlist=frozenset({"*"}),
    )

    rules = {rule for rule, _ in network_policy_problems(policy)}

    assert rules == {
        "network_policy.air_gapped_with_allowlist",
        "network_policy.wildcard_allowlist",
        "network_policy.proxy_scheme",
    }
    # The first reported problem is the air gap, because that is the one an
    # operator has to decide about.
    assert validate_network_policy(policy).startswith("network_policy.air_gapped_with_allowlist")


# -- egress decisions -----------------------------------------------------------


def test_an_air_gapped_install_denies_every_host_and_names_the_air_gap() -> None:
    decision = egress_decision(NetworkPolicy(air_gapped=True), "registry.iana.org", port=443)

    assert decision.denied
    assert not decision.allowed
    assert "air-gapped" in decision.reason
    assert "out of band" in decision.reason
    assert decision.host == "registry.iana.org"


def test_a_port_scoped_allowlist_entry_does_not_licence_another_port() -> None:
    """``db.internal:5432`` is not permission to reach ``db.internal`` on 22."""
    policy = NetworkPolicy(
        allowlist_enforced=True, outbound_allowlist=frozenset({"db.internal:5432"})
    )

    assert egress_decision(policy, "db.internal", port=5432).allowed
    assert egress_decision(policy, "db.internal", port=22).denied
    # A caller that did not state a port is asking "is this host reachable at
    # all", and the entry names one.
    assert egress_decision(policy, "db.internal").allowed


def test_egress_fails_closed_when_an_enforced_allowlist_names_nothing() -> None:
    decision = egress_decision(NetworkPolicy(allowlist_enforced=True), "anything.example")

    assert decision.denied
    assert "names no matching entry" in decision.reason
    assert "allowed: nothing" in decision.reason


def test_an_unenforced_policy_permits_egress_and_says_that_is_a_configuration_fact() -> None:
    decision = egress_decision(NetworkPolicy(), "anything.example")

    assert decision.allowed
    assert "not a clearance" in decision.reason


def test_egress_decision_is_total_and_never_raises_on_a_blank_host() -> None:
    decision = egress_decision(NetworkPolicy(air_gapped=True), "   ")

    assert decision.denied
    assert decision.reason == "no host was named"


def test_a_hostname_is_matched_case_insensitively_and_without_its_trailing_dot() -> None:
    policy = NetworkPolicy(allowlist_enforced=True, outbound_allowlist=frozenset({"db.internal"}))

    assert egress_decision(policy, "DB.Internal.").allowed


def test_an_air_gapped_deployment_model_with_a_reachable_policy_is_refused() -> None:
    """The two declarations live in different files, so they are cross-checked."""
    reason = air_gap_refusal(DeploymentModel.AIR_GAPPED, NetworkPolicy())

    assert reason.startswith("deployment_model.air_gapped_without_policy")


def test_an_air_gap_flag_on_an_egress_deployment_model_is_refused_too() -> None:
    reason = air_gap_refusal(DeploymentModel.MANAGED_SAAS, NetworkPolicy(air_gapped=True))

    assert reason.startswith("deployment_model.egress_policy_under_managed_saas")


def test_matching_declarations_produce_no_refusal() -> None:
    assert air_gap_refusal(DeploymentModel.AIR_GAPPED, NetworkPolicy(air_gapped=True)) == ""
    assert air_gap_refusal(DeploymentModel.MANAGED_SAAS, NetworkPolicy()) == ""


# -- deployment models ----------------------------------------------------------


def test_the_air_gapped_profile_is_the_only_one_that_denies_egress() -> None:
    denying = [model for model in DeploymentModel if not deployment_profile(model).requires_egress]

    assert denying == [DeploymentModel.AIR_GAPPED]
    assert deployment_profile(DeploymentModel.AIR_GAPPED).offline_bundle_exchange


def test_the_sandbox_is_a_local_environment_and_nothing_wider() -> None:
    assert SANDBOX_DEPLOYMENT_MODEL is DeploymentModel.LOCAL
    assert [component.value for component in SANDBOX_COMPONENTS] == [
        "frontend",
        "api",
        "database",
        "cache",
        "queue",
        "observability",
    ]


# -- execution mode -------------------------------------------------------------


def test_only_production_mutates() -> None:
    assert [mode for mode in ExecutionMode if mode.mutates] == [ExecutionMode.PRODUCTION]


def test_the_three_demo_modes_share_the_no_mutation_banner() -> None:
    demo_modes = frozenset(
        {ExecutionMode.SIMULATION, ExecutionMode.TRAINING, ExecutionMode.SAFE_DEMO}
    )

    assert demo_modes == DEMO_MODES
    for mode in DEMO_MODES:
        assert NO_MUTATION_PHRASE in mode.marker
        assert not mode.mutates
    assert ExecutionMode.PRODUCTION.marker == "PRODUCTION"
    assert NO_MUTATION_PHRASE not in ExecutionMode.PRODUCTION.marker


def test_the_marker_is_derived_so_a_training_run_cannot_claim_mutation() -> None:
    """The structural property: ``mutates`` comes from the mode, not from a caller."""
    marker = sealed_mode_marker(ExecutionMode.TRAINING, basis="plan 14 simulate path")

    assert marker.mode is ExecutionMode.TRAINING
    assert marker.mutates is False
    assert marker.marker == "TRAINING — no mutation performed"
    assert not marker.may_back_production_evidence
    # The dataclass is frozen, so a sealed value cannot be edited afterwards.
    with pytest.raises(AttributeError):
        marker.mutates = True  # type: ignore[misc]


@pytest.mark.parametrize("mode", sorted(DEMO_MODES, key=lambda m: m.value))
def test_a_demo_mode_run_cannot_be_presented_as_production_evidence(
    mode: ExecutionMode,
) -> None:
    reason = production_presentation_refusal(claim_for(mode, run_id="run-42"))

    assert reason.startswith("evidence.non_production_mode")
    assert "run-42" in reason
    assert mode.marker in reason  # names the banner that would have to be forged
    assert NO_MUTATION_PHRASE in reason


def test_a_production_run_is_presentable_and_a_clean_demo_run_still_is_not() -> None:
    """A demo run whose numbers are perfect is still not a production result."""
    production = claim_for(ExecutionMode.PRODUCTION)
    demo = claim_for(
        ExecutionMode.SAFE_DEMO,
        plan_identity="deadbeef",
        active_flags=frozenset({"demo.mode"}),
    )

    assert production_presentation_refusal(production) == ""
    assert production_presentation_refusal(demo).startswith("evidence.non_production_mode")


def test_the_claim_reads_its_mode_from_the_sealed_marker_and_nowhere_else() -> None:
    claim = claim_for(ExecutionMode.SIMULATION, run_id="run-7")

    # There is no second mode field that could disagree with the sealed marker.
    assert claim.mode is ExecutionMode.SIMULATION
    assert claim.mutates is False
    assert not hasattr(claim, "claimed_mode")


def test_the_marker_digest_is_stable_per_mode_and_not_per_run() -> None:
    first = sealed_mode_marker(ExecutionMode.TRAINING, basis="plan 14")
    second = sealed_mode_marker(ExecutionMode.TRAINING, basis="plan 14")
    production = sealed_mode_marker(ExecutionMode.PRODUCTION, basis="plan 14")

    assert first.digest == second.digest
    assert first.digest != production.digest


def test_flag_drift_cannot_reclassify_sealed_evidence() -> None:
    """The plan's requirement, stated as a refusal: toggling a flag is not a re-run."""
    training_run = claim_for(
        ExecutionMode.TRAINING, run_id="run-9", active_flags=frozenset({"demo.mode"})
    )

    refusal = flag_drift_refusal(training_run, ExecutionMode.PRODUCTION)

    assert refusal.startswith("evidence.flag_drift")
    assert "run-9" in refusal
    assert "demo.mode" in refusal
    # Asking for the mode the run already had is not drift.
    assert flag_drift_refusal(training_run, ExecutionMode.TRAINING) == ""


def test_a_claim_with_no_run_id_is_refused_before_anything_else() -> None:
    claim = ModeClaim(
        run_id="  ",
        marker=sealed_mode_marker(ExecutionMode.PRODUCTION),
        deployment_model=DeploymentModel.LOCAL,
    )

    assert production_presentation_refusal(claim).startswith("evidence.no_run_id")


# -- feature flags --------------------------------------------------------------


def test_every_declared_flag_validates() -> None:
    for flag in FEATURE_FLAGS:
        assert validate_feature_flag(flag) == "", flag.key


def test_a_flag_that_affects_execution_mode_is_refused() -> None:
    flag = FeatureFlag(
        key="demo.force_production",
        summary="Pretend a demo run was a production run",
        default_enabled=False,
        allowed_deployment_models=frozenset({DeploymentModel.LOCAL}),
        affects_execution_mode=True,
    )

    reason = validate_feature_flag(flag)

    assert reason.startswith("feature_flag.execution_mode")
    assert "training run become a production run" in reason


def test_a_flag_that_affects_evidence_presentation_is_refused() -> None:
    flag = FeatureFlag(
        key="report.hide_mode",
        summary="Render a training run's evidence as a production result",
        default_enabled=False,
        allowed_deployment_models=frozenset({DeploymentModel.MANAGED_SAAS}),
        affects_evidence_presentation=True,
    )

    assert validate_feature_flag(flag).startswith("feature_flag.evidence_presentation")


def test_an_undescribed_flag_is_refused() -> None:
    flag = FeatureFlag(
        key="mystery",
        summary="   ",
        default_enabled=False,
        allowed_deployment_models=frozenset({DeploymentModel.LOCAL}),
    )

    assert validate_feature_flag(flag).startswith("feature_flag.key")


def test_a_flag_permitted_in_no_deployment_model_is_refused() -> None:
    flag = FeatureFlag(
        key="nowhere",
        summary="Enabled nowhere",
        default_enabled=False,
        allowed_deployment_models=frozenset(),
    )

    assert validate_feature_flag(flag).startswith("feature_flag.deployment_model")


def test_an_unknown_flag_is_a_planning_error_not_a_key_error() -> None:
    with pytest.raises(LookupError, match="not defined"):
        feature_flag("no.such.flag")


def test_a_demo_only_flag_is_refused_inside_a_production_run() -> None:
    resolution = resolve_flags(
        ["demo.mode"], model=DeploymentModel.LOCAL, mode=ExecutionMode.PRODUCTION
    )

    assert resolution.enabled == frozenset()
    assert [refusal.rule for refusal in resolution.refusals] == ["flag.production_unsafe"]
    assert "does not exist in a production run" in resolution.refusal_for("demo.mode")


def test_the_same_flag_is_granted_in_a_demo_run() -> None:
    resolution = resolve_flags(
        ["demo.mode"], model=DeploymentModel.LOCAL, mode=ExecutionMode.SAFE_DEMO
    )

    assert resolution.enabled == frozenset({"demo.mode"})
    assert resolution.refusals == ()


def test_a_flag_outside_the_deployment_model_is_refused_by_name() -> None:
    resolution = resolve_flags(
        ["offline.bundle_import"], model=DeploymentModel.LOCAL, mode=ExecutionMode.PRODUCTION
    )

    assert [refusal.rule for refusal in resolution.refusals] == ["flag.deployment_model"]
    assert "local" in resolution.refusal_for("offline.bundle_import")


def test_resolution_records_every_refusal_rather_than_raising_on_the_first() -> None:
    resolution = resolve_flags(
        ["demo.mode", "no.such.flag"], model=DeploymentModel.LOCAL, mode=ExecutionMode.PRODUCTION
    )

    assert {refusal.rule for refusal in resolution.refusals} == {
        "flag.unknown",
        "flag.production_unsafe",
    }
    assert resolution.refusal_for("no.such.flag").startswith("feature flag 'no.such.flag'")


def test_feature_flags_for_lists_only_what_the_model_permits() -> None:
    local = {flag.key for flag in feature_flags_for(DeploymentModel.LOCAL)}
    air_gapped = {flag.key for flag in feature_flags_for(DeploymentModel.AIR_GAPPED)}

    assert "sandbox.provisioning" in local
    assert "sandbox.provisioning" not in air_gapped
    assert {"offline.bundle_import", "offline.bundle_export"} <= air_gapped
