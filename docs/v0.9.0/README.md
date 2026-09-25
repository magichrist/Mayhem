# Mayhem v0.9.0 Planning Package

## Status

Planning-only package for the v0.9.0 release line. No implementation is included in this directory.

## Release thesis

**Safe, truthful, replayable execution.**

Mayhem should not grow its fault count blindly. v0.9.0 turns the existing catalog, runtime adapters, safety gates, recovery paths, and evidence model into a product that can explain what it will do, prove what it did, and safely replay or recover from what happened.

## Planning goals

1. Make execution intent explicit for every mutating operation.
2. Make engine and target selection deterministic from plan through evidence.
3. Make capability claims match actual runtime readiness and live evidence.
4. Make every run replayable, redacted, tamper-evident, and auditable.
5. Close Kubernetes admission and conformance gaps without claiming unsupported live coverage.
6. Repair documentation, examples, Justfile recipes, package metadata, and CI as one product surface.
7. Add high-value user workflows: capability truth, coverage deltas, campaign checkpoints, SLO-aware experiments, and safe operator game days.

## Reading order

- [01-vision-and-positioning.md](01-vision-and-positioning.md) — north star, audiences, principles, and non-goals.
- [02-feature-brainstorm.md](02-feature-brainstorm.md) — creative feature portfolio and prioritization.
- [03-gaps-and-standards.md](03-gaps-and-standards.md) — current gaps, standards, compliance, and operational requirements.
- [04-architecture-and-decisions.md](04-architecture-and-decisions.md) — target architecture, data flow, and ADRs.
- [05-release-roadmap.md](05-release-roadmap.md) — phased release plan, dependencies, and exit gates.
- [06-core-implementation-plan.md](06-core-implementation-plan.md) — task-level plan for the P0 safety/truth release slice.
- [07-expansion-implementation-plan.md](07-expansion-implementation-plan.md) — task-level plan for the P1 product expansion slice.
- [08-release-readiness.md](08-release-readiness.md) — Definition of Done and release gates.
- [09-decision-log.md](09-decision-log.md) — accepted decisions, rejected alternatives, and future decision points.
- [10-repository-evidence.md](10-repository-evidence.md) — repository evidence and traceability for the plans.

## Scope boundary

v0.9.0 includes the CLI, library surfaces, Docker/Podman paths, Kubernetes admission and conformance infrastructure, evidence, package, CI, and documentation. It does not claim that every catalog fault is live-verified across every runtime. Live verification remains an explicit, separately authorized conformance result.
