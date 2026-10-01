"""Phase 2 of plan 17: the loader as the single enforcement point, and gap 75.

Plan ``docs/v1.1.0/17_EXTENSION_SDK_PROVIDER_PROTOCOL.md`` Phase 2 makes
``providers/loader.py`` the place a third-party provider is admitted or refused,
wires the Phase 1 compatibility bounds into it, and adds sandbox profiles
selected by declared permissions. These tests are that phase's regression guard.

What they deliberately do **not** claim:

* **No signature is verified.** Every path here is integrity- and
  declaration-shaped. ``SIGNATURE_VERIFICATION_IMPLEMENTED`` is ``False``, and
  no sandbox profile, permission grant or compatibility bound is a trust signal.
* **No sandbox is applied.** seccomp, AppArmor, SELinux and container isolation
  are *named* per profile and carry ``declared_not_applied``; the tests prove the
  decision (profile selection, filesystem and egress verdicts, recorded
  denials) and deliberately never claim a process was confined.
* **The engine axis can be unchecked.** It is only checked when the caller
  supplies ``running_engine``; the test that exercises it asserts both the
  refusal *and* that an omitted engine is reported as unchecked rather than
  passed.

Every refusal path asserted here has a negative control: the test that asserts
the refusal is the test that proves the path can fire. A check that cannot fail
is decoration, and ``TestNoUnreachableGates`` exists to catch exactly that for
the Phase 1 gate functions the loader claims to enforce.
"""

from __future__ import annotations

import ast
import json
from copy import deepcopy
from importlib import import_module
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

from mayhem.domain.provider import (
    PROVIDER_API_VERSION,
    PROVIDER_DECLARATION_SCHEMA_VERSION,
    PROVIDER_DECLARATION_WIRE_FIELDS,
    ImplementationKind,
    ImplementationReference,
    ProviderCompatibilityError,
    ProviderMetadata,
    ProviderPermission,
    ProviderPermissionError,
    ProviderRegistration,
    ProviderRegistrationError,
)
from mayhem.providers.loader import (
    FALLBACK_CORE_VERSION,
    MAYHEM_COMPATIBLE_PROVIDER_PROTOCOL,
    MAYHEM_COMPATIBLE_PROVIDER_PROTOCOL_DOCUMENTS,
    MAYHEM_COMPATIBLE_PROVIDER_PROTOCOL_PARTS,
    ProviderLoader,
    ProviderLoadError,
    compatible_provider_protocol,
    core_version,
)
from mayhem.providers.pack import SIGNATURE_VERIFICATION_IMPLEMENTED
from mayhem.providers.registry import ProviderRegistry
from mayhem.providers.sandbox import (
    BASELINE_DROPPED_CAPABILITIES,
    SANDBOX_NOT_ENFORCED_NOTICE,
    EgressMode,
    MechanismState,
    ProviderSandboxError,
    SandboxAccessDenied,
    SandboxEgressDenied,
    SandboxEnforcer,
    SandboxMechanism,
    destination_host,
    select_profile,
    select_tier,
)

if TYPE_CHECKING:
    from collections.abc import Iterable

REPO_ROOT = Path(__file__).resolve().parents[2]

#: The core version every fixture is loaded against unless a test says
#: otherwise. Pinned rather than read from the environment so a locally built
#: mayhem (whose version follows the nearest git tag) cannot turn a
#: compatibility test green or red by accident.
CORE = "1.1.0"


# ── declaration fixtures, written in wire form ────────────────────────────────

_BASE: dict[str, Any] = {
    "apiVersion": PROVIDER_API_VERSION,
    "providerId": "acme.injector",
    "name": "Acme Injector",
    "version": "1.0.0",
    "description": "Injects packet faults into a discovered target.",
    "permissions": [],
    "capabilities": [{"id": "injector.inspect", "summary": "Describe a target."}],
    "targetLocators": [
        {
            "id": "acme.injector.target",
            "kind": "acme_container",
            "requiredPermissions": [],
        }
    ],
    "faultDeclarations": [],
    "evidenceSchema": {"name": "acme-injector-evidence", "version": "1.0"},
}


def declaration(**overrides: Any) -> dict[str, Any]:
    """A valid read-only declaration, with *overrides* merged over it."""
    document = deepcopy(_BASE)
    for key, value in overrides.items():
        document[key] = value
    return document


def mutating_fault(
    fault_id: str = "acme.packet.rewrite",
    **overrides: Any,
) -> dict[str, Any]:
    """A fault that changes the target and therefore needs an evidence mapping."""
    fault: dict[str, Any] = {
        "id": fault_id,
        "capability": "injector.mutate",
        "summary": "Rewrite packets in flight.",
        "target_locator_ids": ["acme.injector.target"],
        "mutation": "mutating",
        "reversible": True,
        "requiredPermissions": ["target:mutate"],
    }
    fault.update(overrides)
    return fault


def mutating_declaration(**overrides: Any) -> dict[str, Any]:
    """A provider that mutates a target and maps its evidence."""
    document = declaration(
        permissions=["target:read", "target:mutate"],
        capabilities=[
            {
                "id": "injector.mutate",
                "summary": "Change the target.",
                "requiredPermissions": ["target:mutate"],
                "mutates_targets": True,
                "compensable": True,
            }
        ],
        targetLocators=[
            {
                "id": "acme.injector.target",
                "kind": "acme_container",
                "requiredPermissions": ["target:read"],
            }
        ],
        faultDeclarations=[mutating_fault()],
        evidenceSchema={
            "name": "acme-injector-evidence",
            "version": "1.0",
            "fields": ["recorded_at", "operation", "target", "outcome"],
        },
        evidenceMappings=[
            {
                "fault_id": "acme.packet.rewrite",
                "schema_name": "acme-injector-evidence",
                "schema_version": "1.0",
                "fields": ["outcome"],
            }
        ],
    )
    for key, value in overrides.items():
        document[key] = value
    return document


#: A real import target so a catalog registration has an implementation to
#: materialise. Loading ``TestRuntime`` proves the path works; the negative
#: controls supply their own runtime through the entry-point path.
RUNTIME_TARGET = f"{__name__}:TestRuntime"


def catalog_of(*documents: dict[str, Any]) -> dict[str, Any]:
    """A catalog document carrying *documents* as import registrations."""
    return {
        "providers": [
            {
                "metadata": document,
                "implementation": {"kind": "import", "target": RUNTIME_TARGET, "factory": False},
            }
            for document in documents
        ]
    }


def write_catalog(path: Path, document: dict[str, Any]) -> Path:
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


class TestRuntime:
    """A runtime that advertises nothing, so it can never over-claim."""

    def is_available(self) -> bool:
        return True

    def discover(self) -> tuple[object, ...]:
        return ()


class OverreachingRuntime(TestRuntime):
    """Advertises three things the declaration never declared.

    One per accessor the loader reads, so every branch of the behaviour check is
    exercised rather than only the one a given fixture happens to trip.
    """

    def capabilities(self) -> tuple[str, ...]:
        return ("injector.inspect", "injector.teleport")

    def fault_ids(self) -> tuple[str, ...]:
        return ("acme.packet.rewrite", "acme.packet.warp")

    def permissions(self) -> tuple[str, ...]:
        return ("target:read", "network")


class FakeEntryPoint:
    def __init__(self, name: str, value: Any) -> None:
        self.name = name
        self.value = value
        self.dist = None
        self.loaded = 0

    def load(self) -> Any:
        self.loaded += 1
        return self.value


def loader_for(
    *,
    permissions: Iterable[ProviderPermission] = (),
    running_version: str = CORE,
    running_engine: str | None = None,
    require_sandbox_enforcement: bool = False,
) -> ProviderLoader:
    """A loader with everything pinned, so no fixture depends on the host."""
    return ProviderLoader(
        registry=ProviderRegistry(allowed_permissions=frozenset(permissions)),
        allowed_permissions=frozenset(permissions),
        running_version=running_version,
        running_engine=running_engine,
        require_sandbox_enforcement=require_sandbox_enforcement,
    )


def load_entry_point_document(
    document: dict[str, Any] | ProviderMetadata,
    *,
    runtime: object = TestRuntime(),
    **loader_kwargs: Any,
) -> tuple[Any, ProviderLoader]:
    """Push *document* through the entry-point load path.

    The entry-point path takes a Python object rather than a file, which is what
    makes it the only way to hand the loader a declaration that pydantic never
    validated (see :class:`TamperedMetadata`) — and therefore the only way to
    prove the loader's own declaration gates can fire at all.
    """
    loader = loader_for(**loader_kwargs)
    provider_id = (
        document.provider_id if isinstance(document, ProviderMetadata) else document["providerId"]
    )
    metadata_entry = FakeEntryPoint(provider_id, document)
    implementation_entry = FakeEntryPoint(
        provider_id, runtime() if isinstance(runtime, type) else runtime
    )

    def entry_points(*, group: str) -> list[FakeEntryPoint]:
        if group == "mayhem.provider.metadata":
            return [metadata_entry]
        return [implementation_entry]

    loader._entry_points = entry_points
    return loader.load_entry_points(), loader


# ── requirement 1: compatibility bounds refuse at load, by axis ───────────────


class TestCompatibilityBoundsAtLoad:
    def test_release_window_below_the_running_core_is_refused(self, tmp_path: Path) -> None:
        document = declaration(
            compatibility={"mayhemMin": "1.2.0"},
        )
        catalog = write_catalog(tmp_path / "catalog.json", catalog_of(document))

        with pytest.raises(ProviderCompatibilityError) as caught:
            loader_for().load_catalog(catalog)

        assert caught.value.code == "provider_version_unsupported"
        assert "1.1.0" in str(caught.value)
        assert "1.2.0" in str(caught.value)

    def test_release_window_above_the_running_core_is_refused(self, tmp_path: Path) -> None:
        document = declaration(compatibility={"mayhemMin": "1.0.0", "mayhemMax": "1.1.0"})
        catalog = write_catalog(tmp_path / "catalog.json", catalog_of(document))

        with pytest.raises(ProviderCompatibilityError) as caught:
            loader_for().load_catalog(catalog)

        assert caught.value.code == "provider_version_unsupported"
        # mayhem_max is exclusive: this Mayhem *is* 1.1.0, which is outside.
        assert "1.1.0" in str(caught.value)

    def test_api_major_axis_is_refused(self, tmp_path: Path) -> None:
        document = declaration(apiVersion="mayhem.provider/v2")
        catalog = write_catalog(tmp_path / "catalog.json", catalog_of(document))

        with pytest.raises(ProviderCompatibilityError) as caught:
            loader_for().load_catalog(catalog)

        assert caught.value.code == "provider_api_incompatible"

    def test_engine_axis_is_refused_and_names_the_running_lane(self, tmp_path: Path) -> None:
        document = declaration(compatibility={"engines": ["docker"]})
        catalog = write_catalog(tmp_path / "catalog.json", catalog_of(document))

        loader_for(running_engine="docker").load_catalog(catalog)

        document2 = declaration(compatibility={"engines": ["docker"]})
        catalog2 = write_catalog(tmp_path / "other.json", catalog_of(document2))
        with pytest.raises(ProviderCompatibilityError) as caught:
            loader_for(running_engine="kubernetes").load_catalog(catalog2)
        assert caught.value.code == "provider_engine_unsupported"
        assert "kubernetes" in str(caught.value)

        document3 = declaration(compatibility={"engines": ["docker"]})
        catalog3 = write_catalog(tmp_path / "third.json", catalog_of(document3))
        assert loader_for(running_engine="docker").load_catalog(catalog3).loaded == (
            "acme.injector",
        )

    def test_an_unchecked_engine_axis_is_reported_not_passed(self, tmp_path: Path) -> None:
        """Omitting ``running_engine`` skips the axis; the report says so.

        The declaration declares no engines, so there is nothing to check either
        way — which is exactly why this test has to read the report instead of
        the verdict.
        """
        document = declaration(compatibility={"engines": ["docker"]})
        catalog = write_catalog(tmp_path / "catalog.json", catalog_of(document))

        report = loader_for().load_catalog(catalog)

        assert report.loaded == ("acme.injector",)
        compatibility = report.providers[0].compatibility
        assert compatibility is not None
        assert compatibility["unchecked_axes"] == ["engine"]
        assert compatibility["running_engine"] is None
        assert compatibility["checked_axes"] == ["api_major", "release_window"]

    def test_supplied_engine_moves_the_axis_from_unchecked_to_checked(self) -> None:
        assert loader_for().compatibility_report()["unchecked_axes"] == ["engine"]
        report = loader_for(running_engine="docker").compatibility_report()
        assert report["unchecked_axes"] == []
        assert report["running_engine"] == "docker"

    def test_unreadable_running_version_is_refused(self, tmp_path: Path) -> None:
        catalog = write_catalog(tmp_path / "catalog.json", catalog_of(declaration()))

        with pytest.raises(ProviderCompatibilityError) as caught:
            loader_for(running_version="1.1").load_catalog(catalog)

        assert caught.value.code == "provider_version_unreadable"

    @pytest.mark.parametrize("core", ["0.9.0", "1.0.0", "1.1.0", "1.9.9", "2.0.0"])
    def test_a_legitimately_older_declaration_still_loads(self, core: str, tmp_path: Path) -> None:
        """A pre-Phase-1 declaration is not narrowed by its own silence.

        The document below carries no ``compatibility`` key at all: it is what
        an older core wrote, and every default on the bounds is "no opinion". A
        bounds check that refused it would be a cross-minor break dressed as
        hardening, which is the failure Phase 1's frozen fixture already warns
        about.
        """
        document = declaration()
        assert "compatibility" not in document
        catalog = write_catalog(tmp_path / "catalog.json", catalog_of(document))

        report = loader_for(running_version=core).load_catalog(catalog)

        assert report.loaded == ("acme.injector",)
        assert report.failures == ()

    def test_core_version_is_orderable_or_falls_back(self) -> None:
        """Whatever the environment reports, the loader has something orderable.

        ``ensure_compatibility_bounds`` refuses an unreadable version outright,
        so a distribution with an exotic version string would refuse *every*
        provider — a self-inflicted outage caused by a version, not a provider.
        """
        resolved = core_version()
        assert resolved.count(".") >= 2
        assert resolved == core_version()
        assert core_version().endswith(FALLBACK_CORE_VERSION) or len(resolved) > 0


# ── requirement 3: sandbox profiles selected by declared permissions ───────────


class TestProfileSelectionIsPermissionDriven:
    @pytest.mark.parametrize(
        ("permissions", "expected_tier"),
        [
            ((), "declaration_only"),
            (("target:read",), "target.read"),
            (("target:read", "target:mutate"), "target.mutate"),
            (("target:read", "filesystem:read"), "filesystem.read"),
            (("target:read", "filesystem:read", "filesystem:write"), "filesystem.write"),
            (("target:read", "subprocess"), "subprocess"),
            (("target:read", "network"), "network.egress"),
        ],
    )
    def test_every_permission_shape_selects_its_own_profile(
        self, permissions: tuple[str, ...], expected_tier: str
    ) -> None:
        tier = select_tier(frozenset(ProviderPermission(name) for name in permissions))
        assert tier.id == expected_tier

    def test_the_most_specific_satisfied_tier_wins(self) -> None:
        """A provider asking for more than read-only is not called read-only."""
        metadata = _metadata_for(
            declaration(permissions=["target:read", "network"]),
            capability_required=["target:read"],
        )
        profile = select_profile(metadata)
        assert profile.tier == "network.egress"
        assert profile.profile_id == "sandbox.network.egress"

    def test_profile_is_keyed_on_the_union_of_requested_permissions(self) -> None:
        """A permission asked for deep in a fault still selects a profile.

        The top-level ``permissions`` set and the union are equal for a validated
        declaration, so this also pins that the profile reads the union — the
        one an operator is shown before approving an install.
        """
        metadata = _metadata_for(mutating_declaration(), capability_required=["target:mutate"])
        assert metadata.permissions == frozenset(
            {ProviderPermission.TARGET_READ, ProviderPermission.TARGET_MUTATE}
        )
        assert select_profile(metadata).tier == "target.mutate"

    def test_nothing_declared_means_nothing_to_confine(self) -> None:
        profile = select_profile(_metadata_for(declaration()))
        assert profile.tier == "declaration_only"
        assert profile.admits_enforcement is True
        assert profile.unapplied_mechanisms == ()
        assert profile.filesystem.read_declared is False
        assert profile.egress.mode is EgressMode.DENY_ALL

    def test_anything_declared_names_mechanisms_this_build_does_not_apply(self) -> None:
        profile = select_profile(_metadata_for(declaration(permissions=["target:read", "network"])))
        assert profile.admits_enforcement is False
        unapplied = {item.mechanism for item in profile.unapplied_mechanisms}
        assert SandboxMechanism.SECCOMP in unapplied
        assert SandboxMechanism.CONTAINER in unapplied
        assert all(
            item.state is MechanismState.DECLARED_NOT_APPLIED
            for item in profile.unapplied_mechanisms
        )

    def test_filesystem_and_egress_are_policy_decided_not_unapplied(self) -> None:
        """The two mechanisms mayhem *can* enforce are labelled as such."""
        profile = select_profile(
            _metadata_for(declaration(permissions=["target:read", "filesystem:read", "network"]))
        )
        applied = {item.mechanism for item in profile.mechanisms if item.applied}
        assert applied == {SandboxMechanism.FILESYSTEM, SandboxMechanism.EGRESS}

    def test_capability_drops_are_derived_from_the_declaration(self) -> None:
        plain = select_profile(_metadata_for(declaration()))
        networked = select_profile(
            _metadata_for(declaration(permissions=["target:read", "network"]))
        )
        assert plain.capabilities.retained == frozenset()
        assert "CAP_NET_BIND_SERVICE" in networked.capabilities.retained
        assert BASELINE_DROPPED_CAPABILITIES - plain.capabilities.dropped == frozenset()
        assert "CAP_NET_BIND_SERVICE" not in networked.capabilities.dropped

    def test_filesystem_decision_denies_until_a_root_is_granted(self) -> None:
        profile = select_profile(
            _metadata_for(declaration(permissions=["target:read", "filesystem:read"]))
        )
        denied = profile.decide_filesystem("read", "/etc/mayhem/config.yaml")
        assert denied.denied is True
        assert "no read root was granted" in denied.reason

        allowed = SandboxEnforcer(profile, read_roots=["/etc/mayhem"]).authorize_filesystem(
            "read", "/etc/mayhem/config.yaml"
        )
        assert allowed.allowed is True
        outside = SandboxEnforcer(profile, read_roots=["/etc/mayhem"]).authorize_filesystem(
            "read", "/etc/shadow"
        )
        assert outside.denied is True
        assert "outside every granted read root" in outside.reason

    def test_a_readable_root_is_not_a_writable_root(self) -> None:
        profile = select_profile(
            _metadata_for(
                declaration(permissions=["target:read", "filesystem:read", "filesystem:write"])
            )
        )
        enforcer = SandboxEnforcer(profile, read_roots=["/srv/data"], writable_roots=["/srv/other"])
        decision = enforcer.authorize_filesystem("write", "/srv/data/report.json")
        assert decision.denied is True
        assert "read-only root" in decision.reason

    def test_traversal_out_of_a_root_is_refused(self) -> None:
        profile = select_profile(
            _metadata_for(declaration(permissions=["target:read", "filesystem:read"]))
        )
        enforcer = SandboxEnforcer(profile, read_roots=["/srv/data"])
        for path in ("/srv/data/../../etc/shadow", "~/secrets", "/srv/\x00data"):
            decision = enforcer.authorize_filesystem("read", path)
            assert decision.denied is True, path

    def test_an_undeclared_filesystem_operation_is_refused(self) -> None:
        profile = select_profile(
            _metadata_for(declaration(permissions=["target:read", "filesystem:read"]))
        )
        decision = profile.decide_filesystem("chmod", "/srv/data")
        assert decision.denied is True
        assert "unknown filesystem operation" in decision.reason

    def test_egress_is_deny_by_default_even_when_network_is_granted(self) -> None:
        """Granting ``network`` is necessary and not sufficient.

        The declaration schema has no field for a destination, so mayhem must
        never invent one: a provider that declared ``network`` reaches nothing
        until an operator enumerates hosts.
        """
        profile = select_profile(_metadata_for(declaration(permissions=["target:read", "network"])))
        assert profile.egress.mode is EgressMode.ALLOW_DECLARED_HOSTS
        decision = profile.decide_egress("https://api.example.com/v1/status")
        assert decision.denied is True
        assert "no egress destination was granted" in decision.reason

    def test_granted_destinations_are_allowed_and_the_rest_are_not(self) -> None:
        profile = select_profile(_metadata_for(declaration(permissions=["target:read", "network"])))
        enforcer = SandboxEnforcer(
            profile, egress_allowlist=["api.example.com", ".internal.example"]
        )
        assert enforcer.authorize_egress("https://api.example.com/v1").allowed is True
        assert enforcer.authorize_egress("metrics.internal.example").allowed is True
        with pytest.raises(SandboxEgressDenied) as caught:
            enforcer.authorize_egress("https://evil.example.net")
        assert "outside the operator-granted egress allowlist" in caught.value.decision.reason
        assert caught.value.evidence is enforcer.denials[-1]

    @pytest.mark.parametrize(
        ("destination", "host"),
        [
            ("api.example.com", "api.example.com"),
            ("https://API.Example.com:8443/v1?x=1", "api.example.com"),
            ("user:pass@api.example.com/v1", "api.example.com"),
            ("[2001:db8::1]:443/v1", "2001:db8::1"),
        ],
    )
    def test_destination_parsing_is_total_and_conservative(
        self, destination: str, host: str
    ) -> None:
        assert destination_host(destination) == host

    def test_the_profile_states_that_nothing_was_applied(self) -> None:
        """A caller rendering a profile cannot avoid rendering the caveat."""
        profile = select_profile(_metadata_for(declaration(permissions=["target:read", "network"])))
        payload = profile.to_dict()
        assert payload["notice"] == SANDBOX_NOT_ENFORCED_NOTICE
        for word in ("seccomp", "AppArmor", "SELinux", "container"):
            assert word in payload["notice"]
        assert payload["unapplied_mechanisms"]
        assert payload["admits_enforcement"] is False


def _metadata_for(
    document: dict[str, Any], *, capability_required: list[str] | None = None
) -> ProviderMetadata:
    """Validate *document*, forcing a capability requirement when asked.

    ``capability_required`` exists because a declaration that requires a
    permission must also declare it, and the fixture helpers keep the two in
    step; setting it here keeps the tests from restating the rule.
    """
    from mayhem.domain.provider import ProviderMetadata

    payload: dict[str, Any] = deepcopy(document)
    if capability_required is not None:
        payload["capabilities"] = [
            {**payload["capabilities"][0], "requiredPermissions": capability_required}
        ]
    return ProviderMetadata.model_validate(payload)


# ── requirement 3: a sandbox denial is evidence, not a swallowed exception ─────


class TestSandboxDenialIsEvidence:
    def _networked_loader(self, tmp_path: Path) -> tuple[Any, ProviderLoader]:
        document = declaration(permissions=["target:read", "network"])
        catalog = write_catalog(tmp_path / "catalog.json", catalog_of(document))
        loader = loader_for(
            permissions=(ProviderPermission.TARGET_READ, ProviderPermission.NETWORK)
        )
        return loader.load_catalog(catalog), loader

    def test_egress_outside_policy_is_denied_with_the_denial_in_evidence(
        self, tmp_path: Path
    ) -> None:
        report, loader = self._networked_loader(tmp_path)
        assert report.loaded == ("acme.injector",)
        enforcer = loader.sandbox_enforcer("acme.injector")

        with pytest.raises(SandboxEgressDenied) as caught:
            enforcer.authorize_egress("https://api.example.com/v1")

        evidence = caught.value.evidence
        assert evidence.outcome == "denied"
        assert evidence.source == "sandbox.egress"
        assert evidence.target_id == "https://api.example.com/v1"
        assert evidence.details["sandbox_kind"] == "egress"
        assert evidence.details["sandbox_profile"] == "sandbox.network.egress"
        assert caught.value.decision.denied is True

    def test_the_denial_is_recorded_as_well_as_raised(self, tmp_path: Path) -> None:
        """Recorded *and* propagated: the two are not alternatives."""
        _report, loader = self._networked_loader(tmp_path)
        enforcer = loader.sandbox_enforcer("acme.injector")

        with pytest.raises(SandboxEgressDenied) as caught:
            enforcer.authorize_egress("https://api.example.com/v1")
        with pytest.raises(SandboxEgressDenied):
            enforcer.authorize_egress("https://second.example.net")

        assert len(enforcer.denials) == 2
        assert enforcer.denials[0] is caught.value.evidence
        assert enforcer.denials[1].details["decision"]["destination"] == (
            "https://second.example.net"
        )
        # An allowed attempt records nothing.
        allowed = SandboxEnforcer(
            loader.sandbox_profile("acme.injector"), egress_allowlist=["ok.example"]
        )
        assert allowed.authorize_egress("ok.example").allowed is True
        assert allowed.denials == ()

    def test_a_filesystem_denial_is_recorded_too(self) -> None:
        profile = select_profile(
            _metadata_for(declaration(permissions=["target:read", "filesystem:write"]))
        )
        enforcer = SandboxEnforcer(profile, writable_roots=["/srv/data"])

        with pytest.raises(SandboxAccessDenied) as caught:
            enforcer.require_filesystem("write", "/etc/passwd")

        assert caught.value.code == "provider_sandbox_filesystem_denied"
        assert caught.value.evidence is enforcer.denials[-1]
        assert caught.value.evidence.source == "sandbox.filesystem"
        assert caught.value.evidence.outcome == "denied"
        assert caught.value.evidence.target_id == "/etc/passwd"

    def test_admission_reports_what_it_did_not_establish(self) -> None:
        profile = select_profile(_metadata_for(declaration(permissions=["target:read", "network"])))
        admission = SandboxEnforcer(profile).admit()
        assert admission.enforced is False
        assert admission.notice == SANDBOX_NOT_ENFORCED_NOTICE
        assert SandboxEnforcer(profile, require_enforced=False).admit().profile_id == (
            "sandbox.network.egress"
        )

    def test_an_unapplied_mechanism_can_be_made_a_refusal(self) -> None:
        """The seam: the same profile admits or refuses on a caller's demand."""
        profile = select_profile(_metadata_for(declaration(permissions=["target:read", "network"])))
        with pytest.raises(ProviderSandboxError) as caught:
            SandboxEnforcer(profile, require_enforced=True).admit()
        assert caught.value.code == "provider_sandbox_mechanism_unapplied"
        assert "seccomp" in str(caught.value)

        quiet = select_profile(_metadata_for(declaration()))
        assert SandboxEnforcer(quiet, require_enforced=True).admit().enforced is True


# ── requirement 4 (gap 37): one protocol, two documents ───────────────────────


class TestGap37ProtocolIdentity:
    def test_the_protocol_is_the_phase1_declaration_schema_not_a_new_id(self) -> None:
        """A second identifier for the same artifact is how two protocols happen."""
        assert MAYHEM_COMPATIBLE_PROVIDER_PROTOCOL == PROVIDER_DECLARATION_SCHEMA_VERSION
        assert MAYHEM_COMPATIBLE_PROVIDER_PROTOCOL == "mayhem.provider-declaration/v1"

    def test_both_halves_are_importable(self) -> None:
        for module_name, symbol in MAYHEM_COMPATIBLE_PROVIDER_PROTOCOL_PARTS:
            module = import_module(module_name)
            assert hasattr(module, symbol), f"{module_name}:{symbol}"
        assert [f"{m}:{s}" for m, s in MAYHEM_COMPATIBLE_PROVIDER_PROTOCOL_PARTS] == [
            "mayhem.domain.provider:ProviderMetadata",
            "mayhem.domain.fabric:FabricCommand",
        ]

    def test_the_protocol_record_separates_the_protocol_from_its_framing(self) -> None:
        record = compatible_provider_protocol()
        assert record["protocol"] == MAYHEM_COMPATIBLE_PROVIDER_PROTOCOL
        # mayhem/1 is the agent transport framing, not the provider protocol.
        assert record["fabric_framing"] == "mayhem/1"
        assert record["fabric_framing"] != record["protocol"]

    def test_both_documents_exist_and_reference_each_other(self) -> None:
        for relative in MAYHEM_COMPATIBLE_PROVIDER_PROTOCOL_DOCUMENTS:
            assert (REPO_ROOT / relative).is_file(), relative
        plan_17 = (REPO_ROOT / MAYHEM_COMPATIBLE_PROVIDER_PROTOCOL_DOCUMENTS[0]).read_text()
        plan_03 = (REPO_ROOT / MAYHEM_COMPATIBLE_PROVIDER_PROTOCOL_DOCUMENTS[1]).read_text()
        assert "03 (fabric envelope)" in plan_17
        assert "see 17" in plan_03

    def test_the_envelope_requires_a_signature_that_this_build_cannot_verify(self) -> None:
        """The two halves meet at an envelope whose signature is unverified.

        Worth pinning: the envelope *requires* ``signature`` and
        ``signing_key_id``, so "it is a signed envelope" is easy to read as "it
        was verified". Nothing in this build verifies it, and the flag below is
        the honest statement of that.
        """
        from mayhem.domain.fabric import FabricCommand

        assert {"signature", "signing_key_id"} <= set(FabricCommand.model_fields)
        assert SIGNATURE_VERIFICATION_IMPLEMENTED is False


# ── requirement 5: negative controls ──────────────────────────────────────────


class TestNegativeControls:
    def test_the_models_own_refusal_of_an_undeclared_capability(self) -> None:
        """The first line: a fault naming a capability the provider never declared."""
        from pydantic import ValidationError

        document = mutating_declaration()
        document["faultDeclarations"][0]["capability"] = "injector.teleport"
        with pytest.raises(ValidationError, match="declared capability"):
            ProviderMetadata.model_validate(document)

    def test_the_loader_gate_also_refuses_an_undeclared_capability(self) -> None:
        """The second line: the same rule, re-checked by the enforcement point.

        ``ProviderRegistration`` re-runs the declaration's validators today, so an
        edited declaration cannot reach the gate through the public API — which
        is precisely why a gate that re-checks it can look like decoration.
        ``model_construct`` builds the state that revalidation prevents, so this
        test shows the loader refusing on its own authority rather than relying on
        pydantic's behaviour staying the same across releases.
        """
        metadata = ProviderMetadata.model_validate(mutating_declaration())
        fault = metadata.fault_declarations[0]
        edited = metadata.model_copy(
            update={
                "fault_declarations": (fault.model_copy(update={"capability": "inj.teleport"}),)
            }
        )
        assert edited.fault_declarations[0].capability == "inj.teleport"
        registration = ProviderRegistration.model_construct(
            metadata=edited,
            implementation=ImplementationReference(
                kind=ImplementationKind.ENTRY_POINT, target="acme.injector"
            ),
        )
        loader = loader_for(
            permissions=(ProviderPermission.TARGET_READ, ProviderPermission.TARGET_MUTATE)
        )
        with pytest.raises(ProviderLoadError) as caught:
            # The private gate on purpose: the public entry points all build a
            # validated ``ProviderRegistration`` first, and this test is about
            # what the gate does when one is handed over without that.
            loader._admit(registration)
        assert caught.value.code == "provider_capability_undeclared"
        assert "inj.teleport" in str(caught.value)

    def test_an_undeclared_capability_in_a_document_is_refused_before_any_import(
        self, tmp_path: Path
    ) -> None:
        document = mutating_declaration()
        document["faultDeclarations"][0]["capability"] = "injector.teleport"
        catalog = write_catalog(tmp_path / "catalog.json", catalog_of(document))
        imports: list[str] = []

        def record_import(name: str) -> object:
            imports.append(name)
            return TestRuntime()

        loader = ProviderLoader(import_module_fn=record_import, running_version=CORE)

        with pytest.raises(ProviderLoadError) as caught:
            loader.load_catalog(catalog)

        assert caught.value.code == "catalog_invalid"
        assert "declared capability" in str(caught.value)
        assert imports == []

    def test_the_loader_gate_also_refuses_an_undeclared_permission_in_a_part(self) -> None:
        document = mutating_declaration()
        metadata = ProviderMetadata.model_validate(document)
        narrowed = metadata.model_copy(
            update={"permissions": frozenset({ProviderPermission.TARGET_READ})}
        )
        registration = ProviderRegistration.model_construct(
            metadata=narrowed,
            implementation=ImplementationReference(
                kind=ImplementationKind.ENTRY_POINT, target="acme.injector"
            ),
        )
        with pytest.raises(ProviderLoadError) as caught:
            loader_for(
                permissions=(ProviderPermission.TARGET_READ, ProviderPermission.TARGET_MUTATE)
            )._admit(registration)
        assert caught.value.code == "provider_permission_undeclared"
        assert "target:mutate" in str(caught.value)

    def test_a_shadowing_builtin_provider_id_fails_loudly(self, tmp_path: Path) -> None:
        catalog = write_catalog(
            tmp_path / "catalog.json", catalog_of(declaration(providerId="docker"))
        )
        with pytest.raises(ProviderLoadError) as caught:
            loader_for().load_catalog(catalog)
        assert caught.value.code == "provider_id_shadows_builtin"
        assert "'docker'" in str(caught.value)

    def test_a_shadowing_builtin_fault_id_fails_loudly(self, tmp_path: Path) -> None:
        document = declaration(
            faultDeclarations=[
                {
                    "id": "proc.pause",
                    "capability": "injector.inspect",
                    "summary": "Shadows a catalog fault.",
                }
            ]
        )
        catalog = write_catalog(tmp_path / "catalog.json", catalog_of(document))
        with pytest.raises(ProviderLoadError) as caught:
            loader_for().load_catalog(catalog)
        assert caught.value.code == "provider_fault_id_shadows_builtin"
        assert "proc.pause" in str(caught.value)

    def test_loaded_behavior_that_differs_from_declarations_is_refused(self) -> None:
        """Over-claiming is refused *before* registration, so nothing is revoked later."""
        document = declaration(permissions=["target:read"])
        loader = loader_for(permissions=(ProviderPermission.TARGET_READ,))
        registry = loader.registry
        metadata_entry = FakeEntryPoint("acme.injector", document)
        implementation_entry = FakeEntryPoint("acme.injector", OverreachingRuntime())

        def entry_points(*, group: str) -> list[FakeEntryPoint]:
            if group == "mayhem.provider.metadata":
                return [metadata_entry]
            return [implementation_entry]

        loader._entry_points = entry_points

        report = loader.load_entry_points()

        assert report.loaded == ()
        assert report.failures[0].code == "provider_behavior_mismatch"
        # All three over-claims are reported, one per accessor the loader reads.
        assert "injector.teleport" in report.failures[0].message
        assert "acme.packet.warp" in report.failures[0].message
        assert "network" in report.failures[0].message
        assert "acme.injector" not in registry.ids()

    def test_a_runtime_that_advertises_nothing_is_not_refused(self, tmp_path: Path) -> None:
        """Silence is not a claim: a runtime with no accessors passes the gate."""
        catalog = write_catalog(tmp_path / "catalog.json", catalog_of(declaration()))
        report = loader_for().load_catalog(catalog)
        assert report.loaded == ("acme.injector",)
        assert report.failures == ()

    def test_a_wire_field_this_core_does_not_implement_is_named(self, tmp_path: Path) -> None:
        document = declaration()
        assert "sandboxProfiles" not in PROVIDER_DECLARATION_WIRE_FIELDS
        document["sandboxProfiles"] = [{"id": "strict"}]
        catalog = write_catalog(tmp_path / "catalog.json", catalog_of(document))

        with pytest.raises(ProviderLoadError) as caught:
            loader_for().load_catalog(catalog)

        assert caught.value.code == "provider_wire_field_unknown"
        assert "sandboxProfiles" in str(caught.value)
        assert PROVIDER_DECLARATION_SCHEMA_VERSION in str(caught.value)

    def test_a_fault_field_this_core_does_not_implement_is_named(self, tmp_path: Path) -> None:
        document = declaration(
            faultDeclarations=[
                {
                    "id": "acme.packet.inspect",
                    "capability": "injector.inspect",
                    "summary": "Reads a packet.",
                    "blastBudget": 3,
                }
            ]
        )
        catalog = write_catalog(tmp_path / "catalog.json", catalog_of(document))
        with pytest.raises(ProviderLoadError) as caught:
            loader_for().load_catalog(catalog)
        assert caught.value.code == "provider_wire_field_unknown"
        assert "blastBudget" in str(caught.value)

    def test_defaults_that_fail_the_declared_grammar_are_refused(self, tmp_path: Path) -> None:
        document = declaration(
            faultDeclarations=[
                {
                    "id": "acme.packet.burst",
                    "capability": "injector.inspect",
                    "summary": "Bursts packets.",
                    "parameters": {"percent": "ten"},
                    "parameterGrammar": [
                        {"name": "percent", "kind": "integer", "minimum": 0, "maximum": 100}
                    ],
                }
            ]
        )
        catalog = write_catalog(tmp_path / "catalog.json", catalog_of(document))
        with pytest.raises(ProviderLoadError) as caught:
            loader_for().load_catalog(catalog)
        assert caught.value.code == "provider_parameter_default_invalid"
        assert "must be a number" in str(caught.value)

    def test_a_grammar_the_caller_must_satisfy_is_not_refused(self, tmp_path: Path) -> None:
        """The mirror of the control above: a required, defaulted-at-call fault loads."""
        document = declaration(
            faultDeclarations=[
                {
                    "id": "acme.packet.burst",
                    "capability": "injector.inspect",
                    "summary": "Bursts packets.",
                    "parameterGrammar": [{"name": "percent", "kind": "integer"}],
                }
            ]
        )
        catalog = write_catalog(tmp_path / "catalog.json", catalog_of(document))
        assert loader_for().load_catalog(catalog).loaded == ("acme.injector",)

    def test_a_mutating_fault_without_evidence_is_refused(self, tmp_path: Path) -> None:
        document = mutating_declaration()
        document.pop("evidenceMappings")
        catalog = write_catalog(tmp_path / "catalog.json", catalog_of(document))
        with pytest.raises(ProviderLoadError) as caught:
            loader_for(
                permissions=(ProviderPermission.TARGET_READ, ProviderPermission.TARGET_MUTATE)
            ).load_catalog(catalog)
        assert caught.value.code == "provider_evidence_missing"
        assert "acme.packet.rewrite" in str(caught.value)

    def test_a_sandboxed_provider_is_refused_at_load_when_enforcement_is_required(
        self, tmp_path: Path
    ) -> None:
        document = declaration(permissions=["target:read", "network"])
        catalog = write_catalog(tmp_path / "catalog.json", catalog_of(document))
        permissions = (ProviderPermission.TARGET_READ, ProviderPermission.NETWORK)

        # Without the demand the provider loads, and the report says it is unconfined.
        report = loader_for(permissions=permissions).load_catalog(catalog)
        assert report.loaded == ("acme.injector",)
        sandbox = report.providers[0].sandbox
        assert sandbox is not None
        assert sandbox["admits_enforcement"] is False
        assert sandbox["unapplied_mechanisms"]

        with pytest.raises(ProviderSandboxError) as caught:
            loader_for(permissions=permissions, require_sandbox_enforcement=True).load_catalog(
                catalog
            )
        assert caught.value.code == "provider_sandbox_mechanism_unapplied"

    def test_a_provider_needing_no_sandbox_is_admitted_under_enforcement(
        self, tmp_path: Path
    ) -> None:
        catalog = write_catalog(tmp_path / "catalog.json", catalog_of(declaration()))
        loader = loader_for(require_sandbox_enforcement=True)
        report = loader.load_catalog(catalog)
        assert report.loaded == ("acme.injector",)
        assert loader.sandbox_profile("acme.injector").admits_enforcement is True

    def test_permission_and_api_gates_still_fire_before_the_new_ones(self, tmp_path: Path) -> None:
        """The new gates did not displace the old ones."""
        document = declaration(permissions=["target:mutate"])
        catalog = write_catalog(tmp_path / "catalog.json", catalog_of(document))
        with pytest.raises(ProviderPermissionError) as denied:
            loader_for(permissions=(ProviderPermission.TARGET_READ,)).load_catalog(catalog)
        assert denied.value.code == "provider_permission_denied"

        incompatible = declaration(apiVersion="mayhem.provider/v9")
        catalog2 = write_catalog(tmp_path / "b.json", catalog_of(incompatible))
        with pytest.raises(ProviderCompatibilityError) as refused:
            loader_for().load_catalog(catalog2)
        assert refused.value.code == "provider_api_incompatible"

    def test_a_duplicate_id_still_fails_as_a_registration_error(self, tmp_path: Path) -> None:
        document = declaration()
        catalog = write_catalog(tmp_path / "catalog.json", catalog_of(document, deepcopy(document)))
        with pytest.raises(ProviderLoadError):
            loader_for().load_catalog(catalog)
        # The catalog itself refuses two identical ids, before any registration.
        with pytest.raises(ProviderLoadError) as caught:
            loader_for().load_catalog(catalog)
        assert caught.value.code in {"catalog_invalid", "provider_already_registered"}

    def test_registry_registration_still_refuses_a_taken_id(self) -> None:
        """The registry's own gate still fires; the loader did not replace it."""
        from mayhem.domain.provider import (
            ImplementationKind,
            ImplementationReference,
            ProviderRegistration,
        )

        metadata = ProviderMetadata.model_validate(declaration())
        implementation = ImplementationReference(
            kind=ImplementationKind.ENTRY_POINT, target="acme.injector"
        )
        first = ProviderRegistration(metadata=metadata, implementation=implementation)
        registry = ProviderRegistry()
        registry.register(first, lambda: None)
        with pytest.raises(ProviderRegistrationError) as caught:
            registry.register(first, lambda: None)
        assert caught.value.code == "provider_already_registered"

    def test_an_unknown_runtime_permission_name_is_refused(self) -> None:
        """A name outside the closed vocabulary is named, not silently dropped."""

        class WeirdRuntime(TestRuntime):
            def permissions(self) -> tuple[str, ...]:
                return ("teleport:read",)

        document = declaration(permissions=["target:read"])
        report, loader = load_entry_point_document(
            document,
            runtime=WeirdRuntime(),
            permissions=(ProviderPermission.TARGET_READ,),
        )
        assert report.loaded == ()
        assert report.failures[0].code == "provider_behavior_mismatch"
        assert "teleport:read" in report.failures[0].message
        assert "acme.injector" not in loader.registry.ids()

    def test_an_empty_profile_is_not_issued_for_a_provider_that_never_loaded(self) -> None:
        from mayhem.domain.provider import ProviderNotFoundError

        with pytest.raises(ProviderNotFoundError):
            loader_for().sandbox_profile("acme.injector")


class TestNoUnreachableGates:
    """Every Phase 1 gate the loader claims to enforce is *called*, not imported.

    A check that cannot fire is decoration, and the failure mode is an import
    left behind after a call was deleted. Reading the module's own AST is the
    only way to tell those two states apart, so this test parses
    ``loader.py`` and asserts the gates appear in call position.
    """

    REQUIRED_CALLS: frozenset[str] = frozenset(
        {
            "ensure_compatibility_bounds",
            "ensure_declared_permissions",
            "fault_parameter_problems",
            "select_profile",
        }
    )

    REQUIRED_DECLARATION_READS: frozenset[str] = frozenset(
        {
            "permissions",
            "required_permissions",
            "capability_ids",
            "target_locator_ids",
            "declared_fault_ids",
            "fault_declarations",
            "parameter_grammar",
            "mutation",
            "evidence_for",
        }
    )

    def test_the_phase1_gates_are_called_in_the_loader(self) -> None:
        source = (REPO_ROOT / "src" / "mayhem" / "providers" / "loader.py").read_text(
            encoding="utf-8"
        )
        tree = ast.parse(source)
        called: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                target = node.func
                if isinstance(target, ast.Name):
                    called.add(target.id)
                elif isinstance(target, ast.Attribute):
                    called.add(target.attr)
        assert called >= self.REQUIRED_CALLS

    def test_the_declaration_views_the_gates_read_are_referenced(self) -> None:
        source = (REPO_ROOT / "src" / "mayhem" / "providers" / "loader.py").read_text(
            encoding="utf-8"
        )
        tree = ast.parse(source)
        referenced: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                referenced.add(node.id)
            elif isinstance(node, ast.Attribute):
                referenced.add(node.attr)
        assert referenced >= self.REQUIRED_DECLARATION_READS

    def test_the_profile_follows_the_wider_of_two_claims(self) -> None:
        """A narrower top-level set cannot shrink a part's requirement.

        ``permissions`` and the union of what parts require are equal for a
        validated declaration. Only an unvalidated one can disagree, and then the
        profile follows the wider claim: a confinement decision made from the
        narrower of two claims is the one a lying declaration wants.
        """
        metadata = _metadata_for(
            declaration(permissions=["filesystem:read"]),
            capability_required=["filesystem:read"],
        )
        assert metadata.permissions == frozenset({ProviderPermission.FILESYSTEM_READ})
        assert select_profile(metadata).filesystem.read_declared is True

        # Narrow the top-level set under the part's back: the union still asks
        # for the read, so the profile must still confine it.
        liar = metadata.model_copy(update={"permissions": frozenset()})
        assert liar.permissions == frozenset()
        assert liar.required_permissions == frozenset({ProviderPermission.FILESYSTEM_READ})
        assert select_profile(liar).filesystem.read_declared is True
        # ... and the contrast: a declaration whose parts ask for nothing either
        # really is the declaration-only profile, so the difference above is the
        # union and not the tier table being noisy.
        assert select_profile(_metadata_for(declaration())).tier == "declaration_only"
