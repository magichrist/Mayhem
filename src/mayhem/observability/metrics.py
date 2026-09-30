"""Turning a declared steady-state signal into a number, through the observation layer.

Plan 03 names signal extraction as the bulk of the work and the risk that cannot
be avoided: *"`metric: latency_ms` needs a defined source per observability
kind. This is the bulk of the work and it is unavoidably per-source."* This
module is that per-source resolution table, and nothing else.

It deliberately does **not** invent a transport. Every reading it produces is
carried on :class:`mayhem.domain.observations.ObservationResult` — the same
contract ``PrometheusConnector.observe`` already returns and the same one
``SloCriterion.evaluate`` already consumes — so a signal is read exactly the way
a criterion is read. A steady-state baseline and an SLO threshold are the same
question asked twice, and the second ask should not need a second client.

Three resolutions exist, and no more:

``prometheus``/``metrics``
    The metric name *is* the sample. The connector already parsed it.

``logs``
    A **derived** metric, named explicitly. ``status_5xx_ratio`` — the ratio of
    5xx lines to all lines in the captured tail — is the one the plan's own
    example uses, and it is genuinely a different number from any single line.
    A log source asked for a metric with no derivation is refused by name
    rather than guessed at, because a log tail has no obvious reading and a
    plausible-looking wrong one is worse than no reading.

``probe``/``inspection``
    **Not numerically extractable**, and this says so. ``verify_probes`` answer
    "satisfied: true", which is a boolean, not a latency. Substituting ``0.0``
    would make an unfired probe look like a healthy measurement — the precise
    confusion (``domain.steady_state``) exists to remove. The caller receives
    ``MISSING``, which grades as *insufficient* rather than as *no-effect*.

Every path returns :class:`Measurement` rather than a bare float, so a missing
reading is a value a reader can be told about instead of a ``0.0`` that reads
as a measurement. ``coerce_finite`` is the single gate every reading passes
through: ``nan`` and ``inf`` are refused here, at the boundary, because the
whole tolerance model downstream treats them as unmeasurable and a bundle
cannot be asked to interpret them.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from math import isfinite
from typing import TYPE_CHECKING, Any

from mayhem.domain.common import utc_now
from mayhem.domain.observability import duration_seconds
from mayhem.domain.observations import (
    PROVENANCE_LOCAL,
    ObservationProvider,
    ObservationQuery,
    ObservationResult,
    ObservationStatus,
    collect,
)

if TYPE_CHECKING:
    from mayhem.domain.steady_state import SteadyStateSignal

__all__ = [
    "DERIVED_LOG_METRICS",
    "Measurement",
    "coerce_finite",
    "derive_log_metric",
    "measure_signal",
    "signal_query",
    "unmeasurable_reason",
]


#: Metrics computable from a captured log tail, by declared name.
#:
#: One entry today because one is genuinely needed (plan 03's own example) and
#: because an empty table would be an admission, not a feature: the honest
#: position is that most log-derived metrics are not yet defined per kind.
DERIVED_LOG_METRICS: dict[str, str] = {
    "status_5xx_ratio": "5xx response lines divided by all response lines in the tail",
}

#: The HTTP status token of one response line.
#:
#: Matched as a *standalone* three-digit token, which is what distinguishes a
#: status code from a latency sitting next to it: in ``GET /a 200 200ms`` the
#: ``200ms`` has no word boundary after the digits, so only the real status
#: matches. Codes outside 100-599 are skipped, which is what keeps a log
#: timestamp (``T00:00:00``) from being counted as a request.
_STATUS_TOKEN = re.compile(r"(?<![\d.])(\d{3})(?![\d.])")


def coerce_finite(value: object) -> float | None:
    """Return ``value`` as a finite float, or ``None`` when it is not a number.

    The single gate through which every reading passes. It refuses three
    distinct things for the same reason — none of them is a measurement:

    * a non-``float`` (``None``, a string, a bool) — there is nothing to grade;
    * ``nan`` — a probe that computed an undefined ratio captured nothing;
    * ``inf`` — a division by a zero that reached the wire, which is not valid
      JSON for a strict parser and compares ``True`` against every bound.

    A refused reading becomes ``MISSING`` at the call site, which grades as
    *insufficient*. It never becomes ``0.0``.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    return number if isfinite(number) else None


@dataclass(frozen=True, slots=True)
class Measurement:
    """One reading of one declared signal, with its provenance.

    ``value is None`` is a first-class outcome, not a failure to fill in a
    field: it means the source could not produce a number a reader could
    interpret, and ``detail`` says which of the several reasons applied.
    """

    name: str
    value: float | None
    status: ObservationStatus = ObservationStatus.OK
    provenance: str = PROVENANCE_LOCAL
    source: str = ""
    detail: str = ""
    at: str = ""

    @property
    def available(self) -> bool:
        return self.status is ObservationStatus.OK and self.value is not None

    @classmethod
    def from_observation(cls, name: str, result: ObservationResult, *, at: str = "") -> Measurement:
        """Narrow an :class:`ObservationResult` into a ``Measurement``.

        The ``value is None`` case keeps the provider's own status rather than
        being flattened: a connector that *failed* (``ERROR``) is a different
        fact from one that had nothing to report (``MISSING``), and a baseline
        capture wants to be able to say which. The one downgrade is a provider
        claiming ``OK`` while reporting no value — a contradiction, resolved to
        ``MISSING`` rather than believed.
        """
        if result.value is None and result.status is ObservationStatus.OK:
            status = ObservationStatus.MISSING
        else:
            status = result.status
        return cls(
            name=name,
            value=coerce_finite(result.value),
            status=status,
            provenance=result.provenance,
            source=result.source,
            detail=result.detail,
            at=at or utc_now().isoformat(),
        )

    def to_observation(self) -> ObservationResult:
        """Project back onto the shared observation contract."""
        return ObservationResult(
            metric=self.name,
            value=self.value,
            unit="",
            window_s=0.0,
            status=self.status,
            provenance=self.provenance,
            source=self.source,
            detail=self.detail,
        )

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["status"] = self.status.value
        payload["available"] = self.available
        return payload


def unmeasurable_reason(kind: str, metric: str) -> str:
    """Why a source kind cannot yield a number for ``metric``.

    Named, not generic. "measurement unavailable" tells an operator nothing
    about whether to fix the metric name, the source, or the drill — and the
    answer differs per kind.
    """
    if kind in ("logs",):
        return (
            f"source kind 'logs' yields no reading for metric {metric!r}: log tails "
            f"only derive {', '.join(sorted(DERIVED_LOG_METRICS)) or 'no metrics yet'}"
        )
    return (
        f"source kind {kind!r} yields no numeric reading for metric {metric!r}: "
        "probes and inspect output are not quantities, and inventing one would "
        "make an unfired probe indistinguishable from a healthy measurement"
    )


def derive_log_metric(metric: str, text: str) -> float | None:
    """Compute a declared derived metric over a captured log tail.

    Returns ``None`` for an undeclared metric, and for a tail with no countable
    response line — a ``0/0`` would be a fabricated rate, and an error rate of
    zero is precisely the number a reader cannot distinguish from "never
    measured".
    """
    if metric not in DERIVED_LOG_METRICS:
        return None
    total = 0
    five_xx = 0
    for line in text.splitlines():
        status = _status_of(line)
        if status is None:
            continue
        total += 1
        if 500 <= status <= 599:
            five_xx += 1
    if total == 0:
        return None
    return five_xx / total


def _status_of(line: str) -> int | None:
    """The first plausible HTTP status token on one line, or ``None``.

    Access-log lines carry the status as a standalone three-digit token in
    every format mayhem has to read: Apache (``GET /a 200 12``), nginx
    (``"GET /a HTTP/1.1" 500 33``), and the ``status=500`` key=value form. The
    first in-range token on the line is the status in all three.
    """
    for match in _STATUS_TOKEN.finditer(line):
        code = int(match.group(1))
        if 100 <= code <= 599:
            return code
    return None


def signal_query(signal: SteadyStateSignal, *, window_s: float) -> ObservationQuery:
    """Build the provider-neutral query for one declared signal.

    ``baseline_window`` is the author's own override of the capture window and
    is honoured here, so a provider that can only answer over a lookback is
    asked over the right one rather than the drill-wide default.
    """
    window = duration_seconds(signal.baseline_window) if signal.baseline_window else window_s
    return ObservationQuery(
        metric=signal.metric,
        window_s=window,
        unit="",
        target=signal.source_id,
        labels={"source_id": signal.source_id, "signal": str(signal.name)},
    )


def measure_signal(
    signal: SteadyStateSignal,
    *,
    provider: ObservationProvider | None = None,
    window_s: float = 60.0,
    collection_values: tuple[str, ...] = (),
) -> Measurement:
    """Read one signal now, through the existing observation contract.

    Three sources of truth, in order of preference:

    1. ``collection_values`` — a log tail already captured for this signal's
       source, reduced through the declared derived metric.
    2. ``provider`` — any :class:`ObservationProvider` (``PrometheusConnector``
       is one). Routed through :func:`mayhem.domain.observations.collect`, so a
       provider that raises becomes an ``ERROR`` measurement rather than
       escaping into the run.
    3. neither — ``MISSING``, naming what was missing.

    This reads a *single* point. A baseline needs a series; the caller collects
    the series (the observability collector already polls on the declared
    cadence) and reduces it with
    :func:`mayhem.domain.steady_state.sample_baseline`.
    """
    name = str(signal.name)
    if collection_values:
        text = "\n".join(collection_values)
        derived = derive_log_metric(signal.metric, text)
        if derived is None:
            return Measurement(
                name=name,
                value=None,
                status=ObservationStatus.MISSING,
                source=signal.source_id,
                detail=unmeasurable_reason("logs", signal.metric),
            )
        return Measurement(
            name=name,
            value=derived,
            source=signal.source_id,
            provenance="loki",
        )
    if provider is None:
        return Measurement(
            name=name,
            value=None,
            status=ObservationStatus.MISSING,
            source=signal.source_id,
            detail=(
                f"no provider or captured collection supplied for source_id "
                f"{signal.source_id!r}: nothing was read, which is not the same "
                "as reading zero"
            ),
        )
    (result,) = collect(provider, (signal_query(signal, window_s=window_s),))
    return Measurement.from_observation(name, result)
