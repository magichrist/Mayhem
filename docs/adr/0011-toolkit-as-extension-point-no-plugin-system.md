# 0011. Extension Point Is the Toolkit Arsenal — No Plugin Ecosystem

- **Date:** 2026-08-23
- **Status:** Accepted
- **Related:** [ADR-0004](0004-toolkit-capability-registry.md)

## Context

Extensibility is required (future tools, future fault families), and the obvious pattern is a
third-party plugin system (entry points, hooks, registries). The spec explicitly instructs: do NOT
build a traditional plugin ecosystem as the primary mechanism; integrate third-party tools through
the toolkit; keep boundaries flexible for a later plugin layer without core redesign.

## Options considered

1. **Entry-point plugin system from day one.** Rejected: plugin APIs freeze prematurely around an
   unstable core; security surface expands to untrusted code before the safety model is proven;
   maintenance burden of a public API during v0.x churn.
2. **Closed system; refactor to plugins someday.** Rejected: "someday refactors" become rewrites.
3. **Toolkit-first extension model with deliberately plugin-shaped internal seams.** Chosen.

## Decision

- All external tool integration happens through **toolkit manifests + adapters**
  ([ADR-0004](0004-toolkit-capability-registry.md)). New capability = new manifest + adapter class;
  agents never learn about specific tools.
- Fault families extend by adding `FaultDefinition` + `FaultImplementation` pairs to the registry —
  in-tree for now.
- Internal seams are shaped so a future plugin layer is *additive*: `FaultRegistry`,
  `ToolRegistry`, and `Observer` sink interfaces accept registered objects already; moving
  registration from in-tree modules to entry points later touches only loading code.
- Explicit non-goal until v1.0: third-party code execution inside the controller's trust boundary.

## Consequences

- **Positive:** extension story exists immediately (add a tool or fault via PR); no API stability
  debt during rapid v0.x evolution; smaller attack surface.
- **Negative / accepted trade-offs:** external contributors extend by contributing rather than
  side-loading (a feature for safety, a constraint for speed); when plugins arrive, early adopters
  may need minor import-path updates — acceptable pre-1.0.
