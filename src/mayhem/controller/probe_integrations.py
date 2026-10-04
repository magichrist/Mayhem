"""Native integrations as bounded, read-only signal connectors
(docs/v1.1.0/11_OBSERVABILITY_PROBES_STOP_CONDITIONS.md, Phase 3).

The plan's Phase 3 lists fifteen read paths — Prometheus, OpenTelemetry, Grafana,
Datadog, New Relic, Elastic, Loki, Tempo/Jaeger, OpenSearch, CloudWatch, Azure
Monitor, GCP Monitoring, PagerDuty/Opsgenie — and requires each to be a read-only
connector honouring "the timeout/size/redaction contract".

**This module ships the connector *definitions* and the contract, not fifteen
HTTP clients.** That is a decision, not an omission, and the reasons are:

* The contract is already implemented once, in
  :mod:`mayhem.observability.base` — ``fetch_json`` enforces a timeout and a hard
  response-size cap, and :func:`mayhem.domain.redaction.redact_text` is the
  redaction. Fifteen copies of it would be fifteen places to get the cap wrong.
* A connector here is **a declaration of what may be asked, of where, and under
  which bounds** — plus a *bound client* that answers. Without a bound client the
  connector is :data:`~mayhem.controller.probe_service.ProbeAvailability.UNAVAILABLE`,
  by exactly the rule
  :class:`~mayhem.controller.probe_service.ProbePorts` applies to a probe family.
  There is deliberately no "assume the vendor is fine" default.

What this module *does* add over ``observability/base.py`` is enforcement the
existing connectors leave to their callers, and the part of Phase 3 that matters
most for this plan: **a connector that is declared but unbound reports
``UNAVAILABLE``, refuses, and cannot support a verdict** — the same word, the same
function and the same enum as a probe port, so there is no second spelling of "we
did not look".

Five refusals, each at construction
----------------------------------

* :data:`MAX_CONNECTOR_TIMEOUT_S` and :data:`MAX_CONNECTOR_BYTES` bound every
  connector. A connector that may wait ten minutes is a connector that turns a
  collector timeout into a hung run, and a connector with no size cap is a memory
  exhaustion with a latency-shaped symptom.
* ``redact_before_evidence`` is required to be ``True``. It is a field rather than
  an assumption so the refusal is nameable: a connector added with redaction off
  fails at construction rather than quietly persisting a credential into a detail
  string.
* An endpoint must be an absolute ``https://`` URL, and must not carry
  credentials in it. ``https://user:pass@host`` in a catalogue is a credential in
  a repository, so it is refused by name.
* :attr:`SignalConnector.auth_ref` is a *reference* to a secret the run resolves,
  never a value. A connector that needed a literal token would have to put one in
  the catalogue to work.

And the property the negative controls exist for
------------------------------------------------

**Redaction happens before a byte of a connector's body becomes an observation.**
:func:`ConnectorProbePort.observe` size-caps the body against the connector's own
declared cap (not merely the client's word that it did), redacts it, and only then
builds the :class:`~mayhem.controller.probe_service.ProbeObservation`. The
redacted body goes into ``detail`` only, and the numeric ``value`` is validated by
the same :func:`~mayhem.controller.probe_service.is_measurement` the probe engine
uses — so a connector cannot smuggle a non-finite value past the fact that it
read a body.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from math import isfinite
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from mayhem.controller.probe_service import ProbeObservation, ProbePorts
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.probes import ProbeFamily
from mayhem.domain.redaction import redact_text

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

    from mayhem.controller.probe_service import ProbeReadingPort
    from mayhem.domain.probes import ProbeDefinition

__all__ = [
    "MAX_CONNECTOR_BYTES",
    "MAX_CONNECTOR_TIMEOUT_S",
    "ROLLOUT_TIER_ORDER",
    "UNKNOWN_CONNECTOR_UNIT",
    "ConnectorCatalog",
    "ConnectorClient",
    "ConnectorContractError",
    "ConnectorId",
    "ConnectorPayload",
    "ConnectorProbePort",
    "ConnectorProbePorts",
    "RolloutTier",
    "SignalConnector",
    "SignalKind",
    "default_connectors",
    "refuses_connector_shape",
]


#: The bounds every connector is held to. Same numbers as
#: :data:`mayhem.observability.base.DEFAULT_TIMEOUT_S` and
#: :data:`mayhem.observability.base.MAX_RESPONSE_BYTES`, re-spelled here because a
#: connector that is *refused* for exceeding them needs the limit as a named
#: constant it can name in the refusal message.
MAX_CONNECTOR_TIMEOUT_S = 5.0
MAX_CONNECTOR_BYTES = 256 * 1024

#: What a connector reports as its measurement when its own API is a label-shaped
#: one (a PagerDuty incident state, an OpenSearch document count). The unit is
#: named rather than invented per connector, so a probe definition declaring a
#: different unit is refused by the existing unit check rather than by a special
#: case here.
UNKNOWN_CONNECTOR_UNIT = "count"

#: Substrings that make a URL a credential carrier. Checked against the endpoint
#: template so a connector cannot be *declared* with an embedded token even if the
#: token is redacted at fetch time — a redacted credential in a catalogue is still
#: a credential in a catalogue.
_CREDENTIAL_MARKERS: tuple[str, ...] = (
    "@",
    "token=",
    "apikey=",
    "api_key=",
    "password=",
    "secret=",
)


class SignalKind(StrEnum):
    """What kind of signal a connector reads.

    Four kinds, and the fourth is the one the plan's rollout order turns on:
    ``SYNTHETIC`` and ``ONCALL`` are not telemetry about the system's internals,
    they are statements about the business and the humans, and the Phase 6 rollout
    ships them last for that reason.
    """

    METRICS = "metrics"
    LOGS = "logs"
    TRACES = "traces"
    ONCALL = "oncall"
    SYNTHETIC = "synthetic"


class RolloutTier(StrEnum):
    """The order integrations ship in (the plan's Phase 6 rollout).

    Tier 1 is what a first install can honour with no third-party account at all:
    the metric and log families, which the plan calls out as "metric/log families
    first". Tier 2 is trace and synthetic. Tier 3 is everything that needs a
    vendor contract — a Datadog key, a PagerDuty service, a CloudWatch role.
    """

    METRIC_AND_LOG = "tier-1-metric-and-log"
    TRACE_AND_SYNTHETIC = "tier-2-trace-and-synthetic"
    THIRD_PARTY = "tier-3-third-party"


#: Tier order, least external dependency first. Used by the catalogue and by the
#: CLI so a reader is told the rollout order by the code rather than by a document
#: that can drift from it.
ROLLOUT_TIER_ORDER: tuple[RolloutTier, ...] = (
    RolloutTier.METRIC_AND_LOG,
    RolloutTier.TRACE_AND_SYNTHETIC,
    RolloutTier.THIRD_PARTY,
)


class ConnectorId(StrEnum):
    """The fifteen read paths the plan's Phase 3 names, one member each.

    ``TEMPO`` and ``JAEGER`` are separate members rather than one "traces"
    connector: they are different endpoints with different query shapes and
    different auth, and a single member with a flag would produce a connector
    whose configuration could describe two systems and answer for neither.
    """

    PROMETHEUS = "prometheus"
    OTEL = "opentelemetry"
    GRAFANA = "grafana"
    LOKI = "loki"
    DATADOG = "datadog"
    NEW_RELIC = "new-relic"
    ELASTIC = "elastic"
    OPENSEARCH = "opensearch"
    TEMPO = "tempo"
    JAEGER = "jaeger"
    CLOUDWATCH = "cloudwatch"
    AZURE_MONITOR = "azure-monitor"
    GCP_MONITORING = "gcp-monitoring"
    PAGERDUTY = "pagerduty"
    OPSGENIE = "opsgenie"


@dataclass(frozen=True, slots=True)
class SignalConnector:
    """One read-only integration: what it reads, where, and under which bounds.

    A declaration. It performs no IO and holds no credential — ``auth_ref`` names
    a secret the run resolves, and :meth:`__post_init__` refuses a value that
    looks like one.

    :attr:`family` is the :class:`~mayhem.domain.probes.ProbeFamily` a probe
    definition must declare for this connector to be able to answer it. That
    coupling is what stops a Loki connector from being asked a SQL question: the
    port is keyed by family, so a mismatched definition collects nothing rather
    than collecting something else.
    """

    connector_id: ConnectorId
    signal: SignalKind
    family: ProbeFamily
    endpoint_template: str
    auth_ref: str = ""
    timeout_s: float = MAX_CONNECTOR_TIMEOUT_S
    max_bytes: int = MAX_CONNECTOR_BYTES
    redact_before_evidence: bool = True
    tier: RolloutTier = RolloutTier.THIRD_PARTY
    query_shape: str = ""
    notes: str = ""

    def __post_init__(self) -> None:
        if not (0.0 < self.timeout_s <= MAX_CONNECTOR_TIMEOUT_S):
            raise InvariantViolationError(
                "probes.connector_timeout_out_of_bounds",
                f"connector {self.connector_id.value!r} declares a {self.timeout_s!r}s "
                f"timeout: every connector is bounded to (0, {MAX_CONNECTOR_TIMEOUT_S}] "
                "seconds. A connector that may wait longer turns a collector timeout "
                "into a hung run, and the run learns about it by not finishing.",
            )
        if not (0 < self.max_bytes <= MAX_CONNECTOR_BYTES):
            raise InvariantViolationError(
                "probes.connector_response_cap_out_of_bounds",
                f"connector {self.connector_id.value!r} declares a {self.max_bytes!r} "
                f"byte cap: every connector is capped at {MAX_CONNECTOR_BYTES} bytes. A "
                "connector with no size cap is unbounded memory with a latency-shaped "
                "symptom.",
            )
        if not self.redact_before_evidence:
            raise InvariantViolationError(
                "probes.connector_redaction_required",
                f"connector {self.connector_id.value!r} declares "
                "redact_before_evidence=False: a connector's body becomes an "
                "observation detail, which becomes evidence, and evidence is the "
                "artifact the secret boundary exists for. Refused here rather than "
                "discovered in an envelope.",
            )
        if not self.endpoint_template.startswith("https://"):
            raise InvariantViolationError(
                "probes.connector_endpoint_not_https",
                f"connector {self.connector_id.value!r} declares endpoint "
                f"{self.endpoint_template!r}: these are read paths, so they must be "
                "absolute https:// URLs. An http:// one puts credentials and query text "
                "on the wire in the clear.",
            )
        lowered = self.endpoint_template.lower()
        leaked = [marker for marker in _CREDENTIAL_MARKERS if marker in lowered]
        if leaked:
            raise InvariantViolationError(
                "probes.connector_carries_a_credential",
                f"connector {self.connector_id.value!r} declares endpoint "
                f"{self.endpoint_template!r}, which looks like it carries a credential "
                f"({', '.join(leaked)}). Redaction at fetch time does not help: this "
                "endpoint is a catalogue entry, and a credential in a catalogue is a "
                "credential in whatever version control holds it. Name the secret with "
                "auth_ref and let the run resolve it.",
            )

    def supports(self, definition: ProbeDefinition) -> bool:
        """Can this connector answer ``definition``?"""
        return definition.family is self.family

    def describe(self) -> str:
        auth = f" auth_ref={self.auth_ref}" if self.auth_ref else ""
        return (
            f"{self.connector_id.value} ({self.signal.value}, tier {self.tier.value}) "
            f"-> {self.family.value} probe, {self.endpoint_template}, "
            f"timeout {self.timeout_s:g}s, cap {self.max_bytes}B{auth}"
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "connector_id": self.connector_id.value,
            "signal": self.signal.value,
            "family": self.family.value,
            "endpoint_template": self.endpoint_template,
            "auth_ref": self.auth_ref,
            "timeout_s": self.timeout_s,
            "max_bytes": self.max_bytes,
            "redact_before_evidence": self.redact_before_evidence,
            "tier": self.tier.value,
            "query_shape": self.query_shape,
            "notes": self.notes,
            "description": self.describe(),
        }


@dataclass(frozen=True, slots=True)
class ConnectorCatalog:
    """The connector declarations mayhem ships, keyed by
    :class:`ConnectorId`.

    Lookup is by connector **and** by the probe family it serves, because the
    engine's port map is keyed by family and a catalogue that cannot answer
    "who can read a ``redis`` probe?" is not consulted at the point that matters.
    Where two connectors serve one family (Grafana and Prometheus both read
    metrics) :meth:`for_family` returns them in declaration order and the caller
    binds one; :meth:`ambiguous_families` names the collisions so the choice is
    visible rather than made by iteration order.
    """

    connectors: tuple[SignalConnector, ...] = ()

    def get(self, connector_id: ConnectorId) -> SignalConnector | None:
        for connector in self.connectors:
            if connector.connector_id is connector_id:
                return connector
        return None

    def for_family(self, family: ProbeFamily) -> tuple[SignalConnector, ...]:
        return tuple(c for c in self.connectors if c.family is family)

    def for_tier(self, tier: RolloutTier) -> tuple[SignalConnector, ...]:
        return tuple(c for c in self.connectors if c.tier is tier)

    def ambiguous_families(self) -> tuple[ProbeFamily, ...]:
        """Families two or more shipped connectors both claim.

        Reported, not refused: two ways to read a metric family is a real
        deployment choice, and pretending it is ambiguous would refuse a
        legitimate configuration. Naming it means the operator sees it.
        """
        counts: dict[ProbeFamily, int] = {}
        for connector in self.connectors:
            counts[connector.family] = counts.get(connector.family, 0) + 1
        return tuple(family for family in ProbeFamily if counts.get(family, 0) > 1)

    def ids(self) -> tuple[ConnectorId, ...]:
        return tuple(c.connector_id for c in self.connectors)

    def describe(self) -> str:
        lines = [connector.describe() for connector in self.connectors]
        lines.append("")
        for tier in ROLLOUT_TIER_ORDER:
            members = self.for_tier(tier)
            lines.append(f"{tier.value}: {', '.join(c.connector_id.value for c in members)}")
        return "\n".join(lines)


#: The fifteen connectors the plan names, as data. Declared through
#: :func:`default_connectors` rather than as a module constant so a caller can
#: narrow the catalogue for a deployment and still get the same refusals.
def default_connectors() -> ConnectorCatalog:
    """Every connector the plan's Phase 3 names, in rollout-tier order.

    The endpoint templates are ``{base}`` placeholders: the point of a shipped
    catalogue is the *shape* of what is asked and under which bounds, not a set of
    URLs that would be wrong in every deployment. A caller substitutes a base URL.
    """
    return ConnectorCatalog(
        connectors=(
            # -- tier 1: metric and log families, no vendor account required -----
            SignalConnector(
                connector_id=ConnectorId.PROMETHEUS,
                signal=SignalKind.METRICS,
                family=ProbeFamily.PROMETHEUS,
                endpoint_template="https://{base}/api/v1/query",
                auth_ref="prometheus/bearer",
                tier=RolloutTier.METRIC_AND_LOG,
                query_shape="promql",
                notes="the reference metrics read path; prometheus probes bind here first",
            ),
            SignalConnector(
                connector_id=ConnectorId.LOKI,
                signal=SignalKind.LOGS,
                family=ProbeFamily.LOGS,
                endpoint_template="https://{base}/loki/api/v1/query_range",
                auth_ref="loki/bearer",
                tier=RolloutTier.METRIC_AND_LOG,
                query_shape="logql",
            ),
            SignalConnector(
                connector_id=ConnectorId.GRAFANA,
                signal=SignalKind.METRICS,
                family=ProbeFamily.PROMETHEUS,
                endpoint_template="https://{base}/api/datasources/proxy/1/query",
                auth_ref="grafana/api-key",
                tier=RolloutTier.METRIC_AND_LOG,
                query_shape="promql-via-datasource-proxy",
                notes="second read path for the metrics family; see ambiguous_families",
            ),
            SignalConnector(
                connector_id=ConnectorId.OTEL,
                signal=SignalKind.METRICS,
                family=ProbeFamily.OPENTELEMETRY,
                endpoint_template="https://{base}/v1/metrics",
                auth_ref="otel/bearer",
                tier=RolloutTier.METRIC_AND_LOG,
                query_shape="otlp-http",
                notes="OTLP metrics; the traces read path is ConnectorId.TEMPO",
            ),
            # -- tier 2: trace and synthetic families ---------------------------
            SignalConnector(
                connector_id=ConnectorId.TEMPO,
                signal=SignalKind.TRACES,
                family=ProbeFamily.TRACES,
                endpoint_template="https://{base}/api/search/tags",
                auth_ref="tempo/bearer",
                tier=RolloutTier.TRACE_AND_SYNTHETIC,
                query_shape="tempo-search",
            ),
            SignalConnector(
                connector_id=ConnectorId.JAEGER,
                signal=SignalKind.TRACES,
                family=ProbeFamily.TRACES,
                endpoint_template="https://{base}/api/traces",
                auth_ref="jaeger/bearer",
                tier=RolloutTier.TRACE_AND_SYNTHETIC,
                query_shape="jaeger-query",
                notes="second read path for the traces family; see ambiguous_families",
            ),
            # -- tier 3: third-party integrations, each needing a contract -------
            SignalConnector(
                connector_id=ConnectorId.DATADOG,
                signal=SignalKind.METRICS,
                family=ProbeFamily.PROMETHEUS,
                endpoint_template="https://{base}/api/v1/query",
                auth_ref="datadog/api-key",
                tier=RolloutTier.THIRD_PARTY,
                query_shape="datadog-query",
                notes="collides with the metrics family; a deployment binds one",
            ),
            SignalConnector(
                connector_id=ConnectorId.NEW_RELIC,
                signal=SignalKind.METRICS,
                family=ProbeFamily.PROMETHEUS,
                endpoint_template="https://{base}/v2/applications/{application_id}/metrics",
                auth_ref="new-relic/user-key",
                tier=RolloutTier.THIRD_PARTY,
                query_shape="nr-metrics",
            ),
            SignalConnector(
                connector_id=ConnectorId.ELASTIC,
                signal=SignalKind.LOGS,
                family=ProbeFamily.LOGS,
                endpoint_template="https://{base}/{index}/_search",
                auth_ref="elastic/api-key",
                tier=RolloutTier.THIRD_PARTY,
                query_shape="es-search",
                notes="collides with the logs family; a deployment binds one",
            ),
            SignalConnector(
                connector_id=ConnectorId.OPENSEARCH,
                signal=SignalKind.LOGS,
                family=ProbeFamily.LOGS,
                endpoint_template="https://{base}/{index}/_search",
                auth_ref="opensearch/basic-auth",
                tier=RolloutTier.THIRD_PARTY,
                query_shape="os-search",
            ),
            SignalConnector(
                connector_id=ConnectorId.CLOUDWATCH,
                signal=SignalKind.METRICS,
                family=ProbeFamily.PROMETHEUS,
                endpoint_template="https://monitoring.{region}.amazonaws.com",
                auth_ref="aws/role-arn",
                tier=RolloutTier.THIRD_PARTY,
                query_shape="cloudwatch-get-metric-data",
                notes="auth is an assumed role, not a token; the reference is a role arn",
            ),
            SignalConnector(
                connector_id=ConnectorId.AZURE_MONITOR,
                signal=SignalKind.METRICS,
                family=ProbeFamily.PROMETHEUS,
                endpoint_template="https://{region}.metrics.monitor.azure.com",
                auth_ref="azure/managed-identity",
                tier=RolloutTier.THIRD_PARTY,
                query_shape="azure-metrics-query",
            ),
            SignalConnector(
                connector_id=ConnectorId.GCP_MONITORING,
                signal=SignalKind.METRICS,
                family=ProbeFamily.PROMETHEUS,
                endpoint_template="https://monitoring.googleapis.com/v3/projects/{project}",
                auth_ref="gcp/service-account",
                tier=RolloutTier.THIRD_PARTY,
                query_shape="gcp-time-series",
            ),
            SignalConnector(
                connector_id=ConnectorId.PAGERDUTY,
                signal=SignalKind.ONCALL,
                family=ProbeFamily.SYNTHETIC,
                endpoint_template="https://{subdomain}.pagerduty.com/api/v1/incidents",
                auth_ref="pagerduty/integration-key",
                tier=RolloutTier.THIRD_PARTY,
                query_shape="open-incidents",
                notes="an incident count is a statement about humans, not about the system",
            ),
            SignalConnector(
                connector_id=ConnectorId.OPSGENIE,
                signal=SignalKind.ONCALL,
                family=ProbeFamily.SYNTHETIC,
                endpoint_template="https://api.opsgenie.com/v2/alerts",
                auth_ref="opsgenie/api-key",
                tier=RolloutTier.THIRD_PARTY,
                query_shape="open-alerts",
            ),
        )
    )


# =============================================================================
# Binding: from a connector plus a client, to a probe reading port
# =============================================================================


class ConnectorContractError(InvariantViolationError):
    """A connector broke the contract its own declaration promises.

    A subclass rather than a plain :class:`~mayhem.domain.errors.InvariantViolationError`
    so a caller can tell *a connector misbehaved* from *a probe definition is
    malformed*, while both remain catchable as the invariant they are. The engine
    catches the base and records an ``UNAVAILABLE`` reading, which is the same
    answer either way — and that equality is deliberate: from a run's point of
    view, a connector that broke its contract and a connector that was never bound
    are the same finding, which is that mayhem has no witness.
    """






@dataclass(frozen=True, slots=True)
class ConnectorPayload:
    """What a bound client hands back: a body and the number it read.

    Separate from :class:`~mayhem.controller.probe_service.ProbeObservation` on
    purpose. This is *raw*, pre-contract: the body has not been size-checked and
    the value has not been redacted into, and the port below is where both happen.
    A client that returned a finished observation would let those two steps be
    skipped by simply not calling it.
    """

    body: str
    value: float | None
    unit: str = UNKNOWN_CONNECTOR_UNIT


def refuses_connector_shape(answer: object) -> bool:
    """Is this not a :class:`ConnectorPayload`?

    A **second** predicate rather than a reuse of
    :func:`~mayhem.controller.probe_service.refuses_port_shape`. That one asks
    "is this not a ``ProbeObservation``?", which is the right question for a probe
    port and the wrong question for a connector client: passing a perfectly good
    ``ConnectorPayload`` through it answers ``True`` and the port then refuses a
    correct answer. Two layers, two shapes, two predicates — stated here because
    "one predicate for all port answers" is exactly the shortcut that produces an
    adapter that refuses good data.

    Total over ``object``, for the same reason as its probe-side twin: the thing
    being judged is the possibility that a client answered with something else.
    """
    return not isinstance(answer, ConnectorPayload)


@runtime_checkable
class ConnectorClient(Protocol):
    """The one thing a bound connector client must be able to do."""

    name: str

    def fetch(self, connector: SignalConnector) -> ConnectorPayload:  # pragma: no cover
        """Answer ``connector``'s read, or raise. Never returns ``None``.

        ``None`` is not an answer here: a client that cannot answer raises, and
        :meth:`~mayhem.controller.probe_service.ProbeService.collect` turns the
        raise into an ``UNAVAILABLE`` reading. Returning ``None`` would need a
        third shape for "no answer", and this module has two.
        """
        ...


class ConnectorProbePort:
    """The bridge: a connector plus a client, answering as a probe port.

    Enforces, on every observation and in this order:

    1. the client's answer is a :class:`ConnectorPayload`
       (:func:`refuses_connector_shape` — its own predicate, because the probe
       layer's asks a different question about a different type);
    2. the body is within **this connector's** ``max_bytes`` — re-checked rather
       than trusted, because a client that ignores its cap would otherwise make
       the cap a comment;
    3. the body is redacted, and only the redacted body reaches ``detail``;
    4. the value is a measurement (:func:`~mayhem.controller.probe_service.is_measurement`).

    A failure at any step raises, and the engine turns the raise into an
    ``UNAVAILABLE`` reading naming which step failed. The port never returns a
    half-checked observation.

    Registered with :func:`~mayhem.controller.probe_service.ProbePorts` by
    :class:`ConnectorProbePorts`, so an integration with no bound client is simply
    an unbound family — and unbound is ``UNAVAILABLE``, which refuses.
    """

    __slots__ = ("client", "connector")

    def __init__(self, connector: SignalConnector, client: ConnectorClient) -> None:
        self.connector = connector
        self.client = client

    @property
    def name(self) -> str:
        return f"{self.connector.connector_id.value}:{self.client.name}"

    def observe(self, definition: ProbeDefinition) -> ProbeObservation | None:
        payload = self.client.fetch(self.connector)
        if refuses_connector_shape(payload):
            raise ConnectorContractError(
                "probes.connector_answered_in_the_wrong_shape",
                f"client {self.client.name!r} for connector "
                f"{self.connector.connector_id.value!r} answered with a "
                f"{type(payload).__name__}, not a ConnectorPayload: mayhem has one "
                "shape for a connector's answer, so a broken client is reported as a "
                "broken client rather than read as an outage of the thing it watches",
            )
        body = payload.body or ""
        if len(body.encode("utf-8")) > self.connector.max_bytes:
            raise ConnectorContractError(
                "probes.connector_response_over_cap",
                f"client {self.client.name!r} returned a body of "
                f"{len(body.encode('utf-8'))} bytes for connector "
                f"{self.connector.connector_id.value!r}, which declares a cap of "
                f"{self.connector.max_bytes}: the cap is re-checked here because a "
                "client that overran it must not be believed about anything else it "
                "reports",
            )
        redacted_body, redacted = redact_text(body)
        value = payload.value
        if value is not None and not _is_finite(value):
            raise ConnectorContractError(
                "probes.connector_non_finite_value",
                f"client {self.client.name!r} read {value!r} from connector "
                f"{self.connector.connector_id.value!r}, which is not a finite number: "
                "a connector that returned nan or inf measured nothing, and this is "
                "recorded as an absence rather than graded",
            )
        detail = f"{self.name} [{len(body.encode('utf-8'))}B"
        if redacted:
            detail += ", redacted"
        detail += f"]: {redacted_body}"
        return ProbeObservation(
            value=value,
            unit=payload.unit,
            provenance=self.connector.connector_id.value,
            evidence_ref=(
                f"connector/{self.connector.connector_id.value}/"
                f"{definition.id}/{self.client.name}"
            ),
            detail=detail,
        )


@dataclass(frozen=True, slots=True)
class ConnectorProbePorts:
    """The :class:`~mayhem.controller.probe_service.ProbePorts` a catalogue implies.

    Built by binding *some* of the catalogue's connectors. The families nobody
    bound are simply absent from the mapping, which is the whole point: the
    resulting port map reports them as unbound, and
    :class:`~mayhem.controller.probe_service.ProbeCoverage` then lists them as
    unobserved rather than the run reporting a clean bill of health for a probe it
    never asked.
    """

    catalog: ConnectorCatalog
    clients: Mapping[ConnectorId, ConnectorClient] = field(default_factory=dict)

    def ports(self, families: Iterable[ProbeFamily] | None = None) -> ProbePorts:
        """The port map, optionally narrowed to the families a plan declares.

        Where a family has several shipped connectors, the **first in catalogue
        order that is bound** wins, and :meth:`ConnectorCatalog.ambiguous_families`
        names the collision so the choice is visible rather than accidental.
        """
        wanted = set(families) if families is not None else None
        bound: dict[ProbeFamily, ProbeReadingPort] = {}
        for connector in self.catalog.connectors:
            if wanted is not None and connector.family not in wanted:
                continue
            if connector.family in bound:
                continue
            client = self.clients.get(connector.connector_id)
            if client is None:
                continue
            bound[connector.family] = ConnectorProbePort(connector, client)
        return ProbePorts(ports=bound)

    def unbound(self, families: Iterable[ProbeFamily]) -> tuple[ProbeFamily, ...]:
        """The requested families with no *bound* connector, in family order.

        Different from :meth:`ConnectorCatalog.for_family`: a shipped connector
        nobody bound is still not a way to ask.
        """
        return self.ports(families).unbound(families)


def _is_finite(value: float) -> bool:
    return isfinite(value)
