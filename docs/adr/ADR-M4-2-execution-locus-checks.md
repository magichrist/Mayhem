# ADR-M4-2: Execution-locus checks
**Status:** Approved
**Date:** 2026-09-02
**Deciders:** Ali
**Relates to:** ADR-M3-3 (three-locus ExecutionContext), ADR-M4-1 (additive DSL)
## Context
A check tells us something about the *system under test*, but *where* a check runs
is a separate question from *where the fault lands*. A host-locus probe measures the
host (e.g. `sysstat`/CPU), a container-locus probe runs inside the container
(e.g. an in-container `ps`/`curl`), a service-locus probe resolves the compose
service, and a process-locus probe targets a PID. Silently assuming a check runs at
its fault target's locus is the bug ADR-M3-3's target/agent/tool distinction exists
to prevent.
## Decision
- Introduce a `CheckSpec` that declares an explicit `execution` locus
  (`host` / `container` / `service` / `process`) distinct from the fault target's
  locus.
- A check carries one probe type from a closed set: `http`, `tcp`, `process`,
  `metric`, `file` (the historical `http`-only probe is a special case).
- The executor evaluates a check **at its declared locus**: a container-locus
  probe runs inside the container; a host-locus probe runs on the host. A bare
  (unqualified) check **infers** its locus from the fault target (pre-0.3.0
  behaviour) so existing specs keep working without annotation.
- Each `EvaluationResult` is recorded against the check's declared locus and
  written into the journal (reusing the M3 `EvaluationResult` record).
## Consequences
A container-locus check and a host-locus check against the same fault produce
distinct, correctly-scoped measurements. Backward compatibility is preserved:
unqualified checks infer the target locus exactly as today.
