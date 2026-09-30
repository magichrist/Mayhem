# Plan 26 — Competitive Parity Matrix

Use this as a living engineering matrix, not as marketing copy.

| Capability | Mayhem target state | Chaos Mesh reference | Litmus reference | Priority |
|---|---|---|---|---|
| Docker/Podman | Native | Not primary | Not primary | P0 |
| Kubernetes | Native runtime | Native | Native | P0 |
| eBPF/kernel | Provider/native | Deep | Limited | P1 |
| JVM | Provider/native | Deep | Partial | P1 |
| IO/block | Provider/native | Deep | Partial/varies | P1 |
| Time | Partial (skew native; freeze catalog-only) | Deep | Limited | P1 |
| Cloud | Provider-neutral adapters | Broad | Broad/adapter-driven | P1 |
| Hypothesis/probes | Tolerance-first + lifecycle | Workflow checks | Very strong | P0 |
| Safety proof | First-class | Limited | Limited | P0 |
| Compensation contract | Mandatory for accepted faults | Mechanism-specific | Rollback semantics | P0 |
| Damage quota | First-class | Limited | Limited | P0 |
| Emergency stop | First-class | Requires sourcing | Requires sourcing | P0 |
| Cryptographic evidence | Signed/attested | Add-on direction | Add-on direction | P0 |
| Multi-tenancy | Required | Required via Kubernetes patterns | Native product patterns | P0 |
| RBAC | Environment-aware | Kubernetes-native | ChaosCenter/RBAC | P0 |
| Marketplace | Verified artifact model | Existing ecosystem | ChaosHub | P2 |
| Adaptive boundary search | Native | Not core | Not core | P2 |
| Counterexample minimization | Native | Not core | Not core | P2 |
| Resilience regression | Native | Partial | Partial | P1 |
| Incident replay | Native | Integratable | Integratable | P2 |
| Topology risk prediction | Native | Integratable | Integratable | P1 |

## Competitive principle
Do not claim a feature merely because an interface exists. Track each capability as:
`planned -> implemented -> tested -> runtime-verified -> production-certified`.

Cells marked "Requires sourcing" are known unknowns: no lane may cite
them in prose, docs, or UI until a sourced reading replaces the marker.
A matrix cell that cannot name its evidence is a rumor with a border.

## STATUS — planning only, 0%
Matrix opened; Mayhem-column states advance only via 01 records and
24 gates, never by editing this file optimistically.
