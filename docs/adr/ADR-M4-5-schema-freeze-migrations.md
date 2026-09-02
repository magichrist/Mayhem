# ADR-M4-5: Schema freeze + versioned forward migrations
**Status:** Approved
**Date:** 2026-09-02
**Deciders:** Ali
**Relates to:** ADR-M3-1, ADR-M3-8, ADR-M1-10 (store), ADR-0019
## Context
The execution/identity/ownership schema accumulated across M1–M3 (drill/job
records, tracked resources, runtime identities, environment fingerprints,
three-locus ExecutionContext, NetworkPath fingerprints) had been evolving
in place. A dev DB was occasionally dropped to sidestep drift. As the schema
stabilizes and remote/k8s transports arrive later, in-place schema replacement
becomes a data-loss and reproducibility hazard; drills recorded against an old
shape could no longer be replayed or compared.
## Decision
- **Freeze** the M1–M3 execution/identity/ownership schema as the baseline.
- Introduce **versioned forward migrations** in `infra/migrations.py` with an
  explicit sequence and an `up`/`down` contract. A database records its applied
  migration version; on startup the store runs any pending forward migrations in
  order (`migration.py` already sequences `M0001.M0010`, added in M3).
- **No in-place schema replacement beyond this milestone.** Any further shape
  change must ship as a new forward migration, never a drop-and-recreate.
- The M4 additive DSL fields (`checks`/`success`/`observability`/`duration`
  normalisation) land as the next migration version over the frozen baseline.
## Consequences
A database at the frozen schema migrates forward to the M4 schema and a
down-migration restores the baseline; `test_migrations`/`test_store` enforce
both directions. Developers and CI no longer drop dev DBs — they migrate.
