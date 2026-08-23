# 0001. Record Architecture Decisions

- **Date:** 2026-08-23
- **Status:** Accepted

## Context

Tgondi is a long-lived, production-grade open-source chaos engineering framework with potential
commercial evolution. Architectural decisions will be made by multiple contributors over years.
Decisions that live only in chat logs, issue threads, or contributors' heads get re-litigated,
contradicted, and silently violated.

We need a lightweight way to capture *why* the architecture looks the way it does, so future
contributors can (a) understand constraints before proposing changes and (b) challenge decisions
with full context instead of folklore.

## Options considered

1. **No formal record** — decisions scattered across issues/README. Rejected: unverifiable, lossy.
2. **Heavyweight ISO-style design authority with review boards.** Rejected: overhead incompatible
   with an open-source velocity model.
3. **Nygard-format Architecture Decision Records** in-repo (`docs/adr/NNNN-title.md`). Lightweight,
   diffable in PRs, greppable, tooling-friendly.

## Decision

Adopt Nygard-style ADRs.

- One markdown file per decision at `docs/adr/NNNN-lowercase-kebab-title.md`.
- Sections: **Context**, **Options considered**, **Decision**, **Consequences** (+ optional
  **References**).
- Statuses: `Proposed` → `Accepted` | `Superseded by NNNN` | `Deprecated`.
- ADRs are **immutable once Accepted**: changing a decision means writing a new ADR that supersedes
  the old one; never edit history.
- Every Accepted ADR must be reflected in the living documents under `docs/architecture/` and
  `docs/reference/`. Contradictions between an Accepted ADR and a living doc are bugs.
- PRs that change architecture must reference the ADR they implement or propose a new one.

The initial set 0002–0013 records the foundational decisions made during pre-implementation
planning (2026-08-23).

## Consequences

- **Positive:** durable rationale; onboarding speed; architectural drift becomes visible in review;
  decisions are challengeable but not silently reversible.
- **Negative:** small ongoing documentation tax per decision; risk of stale records if supersession
  discipline lapses (mitigated by README change process).
