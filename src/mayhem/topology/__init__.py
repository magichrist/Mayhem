"""Topology discovery pipeline (ADR-0006, ADR-0013).

Providers produce :class:`PartialGraph` fragments; the TopologyService merges
blueprint (compose) with live truth (container engines / host processes) and
emits a drift report.
"""

from mayhem.topology.service import DiscoveryResult, TopologyService

__all__ = ["DiscoveryResult", "TopologyService"]
