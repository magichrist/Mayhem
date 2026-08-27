# Milestone 8 — Operations Arsenal: DNS/TLS/Application + Load/Stress/Fuzz (deferred work)

> **Verdict basis:** `docs/answer2.md` rework items carried out of M6 scope (Q16): DNS/TLS/application fault operations + load/stress/fuzz *generators*, and optionally k8s-execution extension (ADR-M7 seam).
> **Decision locks (grill Q16, Q19, Q18):** authored as a **short, lighter** milestone — furthest out, deliberately under-specified vs M1–M7; DNS/TLS/application + load/fuzz here, NOT in M6; k8s-execution only if/when a k8s driver is needed.

## 1. Goal

The intentional expansion deck. Unlike M1–M7 this is scoped as a forward-documented milestone: the operations that stress *protocols, applications, and traffic* rather than raw container state. It exists so the roadmap is complete and M6 doesn't balloon, and so a future need (e.g., a load-gen or DNS-resilience campaign) has a defined home.

**Out of scope (now):** anything in M1–M7; this file is first-authored as phases to be planned *when the need is real*.

## 2. ADR lock

- **ADR-M8-1 — Operations are distinct from container faults.** DNS/TLS/application/load/fuzz operate *on* a path/protocol/service (often via NetworkPath) rather than on a container's raw process state; they reuse the M2/M3 ownership/fingerprint/cancellation backbone but are modeled as operations, not container faults.
- **ADR-M8-2 — Load/stress/fuzz generators are bounded operations.** A generator is a cancellable, deadline-bound operation over a target (e.g., load a service, fuzz an input surface) with the same no-leftover guarantee as M6; never unbounded.
- **ADR-M8-3 — k8s-execution extension (conditional).** If a k8s driver is ever needed, it implements the ADR-M7-1 `KubernetesAdapter` contract + ADR-M7 fault categories; not until a cluster target is in active use.

## 3. Phases (outline — concrete AC filled when scheduled)

- **Phase 8.1 — DNS / TLS / application fault operations.** `dns.*`, `tls.*`, application-level faults as operations (fingerprinted, cancellable). *Not before M6 lands clean.*
- **Phase 8.2 — Load / stress / fuzz generators.** Bounded, cancellable generators over targets; reuse M6 pressure + M2 cancellation + M5 coverage so an experiment can drive load and observe checks/metrics (M4).
- **Phase 8.3 — k8s execution extension (conditional).** Implements ADR-M7-1/7-3 once a cluster driver is required.

*(No exhaustive task/AC detail here — by design (Q19). Each phase is expanded when scheduled against a real requirement, reusing the discipline from M1–M7: ADR-lock first, then implementation + tests, unit + e2e-where-live, non-breaking.)*

## 4. Testing / DONE stance (Q18)

To be defined when the phase is scheduled; reuse unit + e2e-where-live. If/when k8s execution is added, it requires the live-cluster test harness (ADR-M7 optional stub formalized).

## 5. Risks / open items

- **Scope discipline:** keep these out of M6; the ownership/cleanup semantics differ (operations vs container faults).
- **Fuzz/load are safety-sensitive:** any generator must be bounded + cancellable + fingerprintable before it ships — apply the M6 "no leftovers" DONE gate.
- **Do not over-specify now:** these phases exist on the roadmap to prevent scope creep elsewhere; expand them against real needs, not in the abstract.
