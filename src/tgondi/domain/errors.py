"""Structured domain failures.

Errors are part of the API (ADR-0002 discipline): every refusal or invariant
violation raises a typed error that is safe to render, log, and persist.
"""

from __future__ import annotations


class DomainError(Exception):
    """Base class for all domain-layer failures."""


class InvalidTransitionError(DomainError):
    """A state machine rejected a transition.

    Attributes:
        entity: Kind of stateful entity, e.g. ``"fault_lease"``.
        entity_id: Identifier of the offending instance.
        current: Current state value.
        requested: State value that was requested.
    """

    def __init__(self, entity: str, entity_id: str, current: str, requested: str) -> None:
        self.entity = entity
        self.entity_id = entity_id
        self.current = current
        self.requested = requested
        super().__init__(
            f"{entity} '{entity_id}' cannot transition from '{current}' to '{requested}'"
        )


class InvariantViolationError(DomainError):
    """A documented domain invariant was violated.

    Attributes:
        rule: Stable identifier of the violated invariant, e.g. ``undo_required_before_active``.
        message: Human-readable explanation with enough context to debug.
    """

    def __init__(self, rule: str, message: str) -> None:
        self.rule = rule
        super().__init__(f"[{rule}] {message}")


class TargetResolutionError(DomainError):
    """A declarative target selector matched nothing resolvable."""

    def __init__(self, selector: str, reason: str) -> None:
        self.selector = selector
        super().__init__(f"target selector '{selector}' unresolved: {reason}")


class SchemaValidationError(DomainError):
    """Fault params or experiment spec failed schema validation."""

    def __init__(self, subject: str, reason: str) -> None:
        self.subject = subject
        super().__init__(f"{subject}: {reason}")
