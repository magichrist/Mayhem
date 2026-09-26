"""Local OpenTelemetry span sink (the only write-side connector)."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any, Protocol

#: The lifecycle spans a run must emit, per the task contract.
SPAN_NAMES: tuple[str, ...] = (
    "mayhem.plan",
    "mayhem.approval",
    "mayhem.lease",
    "mayhem.mutation",
    "mayhem.verification",
    "mayhem.compensation",
    "mayhem.evidence",
)


@dataclass(frozen=True, slots=True)
class Span:
    name: str
    run_id: str = ""
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class SpanSink(Protocol):
    def emit(self, span: Span) -> None:  # pragma: no cover - protocol
        ...


class InMemorySpanSink:
    """Collects spans locally. The only 'export' is this process's memory."""

    def __init__(self) -> None:
        self.spans: list[Span] = []

    def emit(self, span: Span) -> None:
        self.spans.append(span)

    def names(self) -> tuple[str, ...]:
        return tuple(span.name for span in self.spans)

    def export_json(self) -> str:
        return json.dumps([span.to_dict() for span in self.spans], sort_keys=True)

    def clear(self) -> None:
        self.spans.clear()


def record_span(
    sink: SpanSink | None,
    name: str,
    run_id: str = "",
    **attributes: Any,
) -> None:
    """Emit one span, redacting attributes first. No-op without a sink."""
    if sink is None:
        return
    from mayhem.observability.base import redacted

    payload = {key: redacted(str(value)) for key, value in attributes.items()}
    sink.emit(Span(name=name, run_id=run_id, attributes=payload))


def missing_spans(present: tuple[str, ...]) -> tuple[str, ...]:
    """Which required lifecycle spans a run failed to emit."""
    return tuple(name for name in SPAN_NAMES if name not in present)
