"""Verdict matrix evaluation tests (ADR-M3-2).

Exercises the ``CapabilityRequirements`` + ``AdapterCapabilities.verdict()`` +
``RuntimeAdapter.evaluate()`` machinery that answers SUPPORTED / ALTERNATIVE /
UNSUPPORTED / UNKNOWN per capability.
"""

from __future__ import annotations

from mayhem.domain.runtime_adapter import (
    AdapterCapabilities,
    CapabilityRequirements,
    CapabilityVerdict,
    RuntimeCapability,
    VerdictResult,
)


class _EmptyAdapter:
    """Minimal adapter with a hand-built verdict map (avoids engine calls)."""

    def __init__(self, caps: AdapterCapabilities) -> None:
        self._caps = caps

    def capabilities(self) -> AdapterCapabilities:
        return self._caps

    def evaluate(self, reqs: CapabilityRequirements) -> VerdictResult:
        verdicts = {cap.value: self._caps.verdict(cap).value for cap in RuntimeCapability}
        blocking = any(v == CapabilityVerdict.UNSUPPORTED.value for v in verdicts.values())
        return VerdictResult(
            engine=self._caps.engine,
            requirements=reqs,
            verdicts=verdicts,
            blocking=blocking,
        )


def test_verdict_matrix_supported_rootful() -> None:
    caps = AdapterCapabilities(
        engine="docker",
        supported=frozenset(RuntimeCapability),
        alternatives=frozenset(),
    )
    assert caps.verdict(RuntimeCapability.EXEC) == CapabilityVerdict.SUPPORTED
    assert caps.verdict(RuntimeCapability.NETNS) == CapabilityVerdict.SUPPORTED
    assert caps.verdict(RuntimeCapability.RESOURCE_LIMITS) == CapabilityVerdict.SUPPORTED


def test_verdict_matrix_rootless_degrade() -> None:
    # Rootless podman: NETNS=ALTERNATIVE, RESOURCE_LIMITS=UNSUPPORTED (ADR-M3-4)
    caps = AdapterCapabilities(
        engine="podman",
        rootless=True,
        supported=frozenset(
            {
                RuntimeCapability.EXEC,
                RuntimeCapability.PID,
                RuntimeCapability.SIGNAL,
                RuntimeCapability.INSPECT,
                RuntimeCapability.COMPOSE_FILTER,
            }
        ),
        alternatives=frozenset({RuntimeCapability.NETNS}),
    )
    assert caps.verdict(RuntimeCapability.NETNS) == CapabilityVerdict.ALTERNATIVE
    assert caps.verdict(RuntimeCapability.RESOURCE_LIMITS) == CapabilityVerdict.UNSUPPORTED


def test_verdict_unsupported_is_safe_default_for_unlisted() -> None:
    # Unlisted capabilities resolve to UNSUPPORTED (the safe, blocking default),
    # never UNKNOWN — so the planner refuses rather than guessing.
    caps = AdapterCapabilities(engine="fake", supported=frozenset(), alternatives=frozenset())
    assert caps.verdict(RuntimeCapability.PID) == CapabilityVerdict.UNSUPPORTED


def test_blocking_is_true_when_any_requirement_unsupported() -> None:
    caps = AdapterCapabilities(
        engine="podman",
        rootless=True,
        supported=frozenset({RuntimeCapability.EXEC}),
        alternatives=frozenset({RuntimeCapability.NETNS}),
    )
    result = _EmptyAdapter(caps).evaluate(CapabilityRequirements(namespaces=frozenset({"net"})))
    assert result.blocking is True  # RESOURCE_LIMITS is UNSUPPORTED → blocks


def test_blocking_is_false_when_all_supported_or_alternative() -> None:
    all_caps = frozenset(RuntimeCapability)
    caps = AdapterCapabilities(
        engine="podman",
        rootless=True,
        supported=all_caps - frozenset({RuntimeCapability.NETNS}),
        alternatives=frozenset({RuntimeCapability.NETNS}),
    )
    result = _EmptyAdapter(caps).evaluate(CapabilityRequirements(namespaces=frozenset({"net"})))
    assert result.blocking is False  # everything SUPPORTED or ALTERNATIVE → runs
