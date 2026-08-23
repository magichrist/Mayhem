# 0010. Network Faults: Tiered Backends Selected by Capability Probing

- **Date:** 2026-08-23
- **Status:** Accepted
- **Related:** [ADR-0004](0004-toolkit-capability-registry.md)

## Context

Network degradation (latency/jitter/loss/corruption/bandwidth/partition/DNS) is the highest-value
fault family, and the hardest to make portable. The canonical tool (`tc netem`) requires
`CAP_NET_ADMIN` in the right network namespace; containers may or may not have it; unprivileged
environments have none of it. A framework that only works when it is root everywhere fails its own
portability goals.

## Options considered

1. **tc-only; require root + NET_ADMIN everywhere.** Rejected: excludes rootless Podman, CI, and
   hardened hosts outright.
2. **Toxiproxy-only (userspace proxy).** Rejected: app must be pointed at the proxy; not
   transparent; no IP-layer partitioning.
3. **Tiered backends behind capability IDs (`net.latency`, `net.partition`, …), selected by probing,
   overridable in config.** Chosen.

## Decision

Backend ladder per network capability, first-available wins:

| Tier | Backend | Needs | Notes |
|---|---|---|---|
| 1 | `tc netem` on target interface inside the container netns (`nsenter` from host, or in-container `tc` when the container holds NET_ADMIN) | CAP_NET_ADMIN | transparent, kernel-grade |
| 2 | iptables/nft rules (DROP/REJECT, marked chains `TGND-<lease>`) | NET_ADMIN | partitions, resets, port blocks |
| 3 | Toxiproxy managed by the toolkit (server lifecycle owned by agent; cleanup guaranteed) | none | latency/toxicity/bandwidth at proxy level |
| 4 | userspace shim / DNS-level overrides (dnsmasq/resolv.conf manipulation) | varies | last-resort degradation modes |

Rules: every tier's mutations carry lease-tagged identifiers; undo steps are written ahead
([ADR-0005](0005-recovery-model-lease-journal-janitor.md)); backend choice is logged in the
observation record ("via tc netem on eth0" vs "via toxiproxy") so evidence interpretation never
guesses. Connection-exhaustion style effects are implemented as load-generation faults, not netem.

## Consequences

- **Positive:** same experiment YAML degrades gracefully across privileged hosts, rootless
  containers, and CI; evidence records name their mechanism.
- **Negative / accepted trade-offs:** semantics differ slightly between tiers (proxy-level vs
  IP-level loss); docs must state per-tier fidelity; toxiproxy lifecycle is another process to
  guarantee cleanup for (covered by toolkit ownership rules).
