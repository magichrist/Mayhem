from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class ProviderRuntime(Protocol):
    @property
    def id(self) -> str: ...

    def is_available(self) -> bool: ...

    def capabilities(self) -> object: ...

    def discover(self) -> object: ...


@runtime_checkable
class FaultRuntime(Protocol):
    def apply_fault(self, invocation: object, target: object) -> object: ...

    def compensate(self, receipt: object) -> object: ...


@runtime_checkable
class TargetLocatorRuntime(Protocol):
    def resolve_target(self, selector: object) -> tuple[object, ...]: ...


@runtime_checkable
class EvidenceRuntime(Protocol):
    def collect_evidence(self, operation: object) -> tuple[object, ...]: ...


class ProviderFactory(Protocol):
    def __call__(self) -> ProviderRuntime: ...
