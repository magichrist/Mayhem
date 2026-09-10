# Mayhem Feature Plan — Part 1 of 5: Context & Grounding

**Status:** planning only (no code changes). Split of `docs/features.md` into `feat-1.md` … `feat-5.md` (2026-09-10); section numbering is preserved so cross-references are stable.

**Where each part lives:**

| Part | File | Sections |
|---|---|---|
| 1 | `feat-1.md` | §1–2 (preamble: product moment, status, inputs) |
| 2 | `feat-2.md` | §3 (explore · next · coverage; invariants P/A/C) |
| 3 | `feat-3.md` | §4–5, §7 (coverage model, failure/determinism, ranking) |
| 4 | `feat-4.md` | §6, §8–10 (engineering handoff, KPIs, CLI, docs) |
| 5 | `feat-5.md` | §11–15 (backlog, vision, foundations, constraints) |

---

## Part 1 — Context & Grounding — contains §1–2


**Status:** planning only (no code changes).

**Inputs:** `docs/re-design.md` (vision), `docs/drill-spec.md`, `CHANGELOG.md`,
live grill-me interview (2026-09-10, decisions marked **[interview]** below),
repository exploration, review pass 1 (2026-09-10, 24 changes applied).

**Product moment we are chasing:** Mayhem stops being a "fault engine you
drive" and becomes a tool that *chooses what to test next*, safely, proves
what happened, and measures how much of your system has been proven. That is
the strongest differentiation available to us — the execution/safety/evidence
loop is already unusually mature; what is missing is the intelligence layer on
top of it.
---

## 1. Where the project is right now (evidence)

### What is genuinely strong

- **The core loop is closed.** `topology → frozen plan → gated injection →
  observe → compensate → machine verdict → SQLite evidence` is real and
  tested (`README.md`, `docs/drill-spec.md`).
- **Fault catalog is wide and gated.** 40+ fault kinds with per-fault risk
  level, max duration, node kinds, required capability, typed parameters
  (`docs/drill-spec.md` Fault Catalog, `mayhem.domain.catalog`).
- **Compensation is a contract, not a hope.** Every planned fault carries
  undo ops; the planner bakes compensation in (`controller/planner.py`),
  (`docs/compensation.md`); the watchdog/janitor sweep dirty and stolen leases
  (`controller/janitor.py`, changelog 0.5.1).
- **Drill DSL is declarative and versioned** (`kind: drill`, `apiVersion:
  mayhem/v1`), with config layering, snapshots, profiles
  (`config.py`, ADR-0008).
- **Verdicts are typed and evidence-backed.** Success criteria → PASS/FAIL
  evaluated over recorded observations (`domain/success.py`,
  `controller/resilience_report.py`, `docs/drill-spec.md`).
- **The intelligence machinery exists but is orphaned from the CLI:**
  - `infra/candidate_generator.py` — `SeededCandidateGenerator` +
    `CandidateLandscape` (deterministic, risk-ceiling aware)
  - `infra/candidate_gates.py` — Safety → Feasibility → Resource-conflict
    pipeline (`domain/candidates.py`)
  - `infra/campaign_engine.py` — M5 campaign lifecycle with `CandidateSource`
    / `Approver` / `Runner` protocols, `autonomous | supervised` modes,
    stop-on `coverage_target | max_runs | deadline`
  - `domain/coverage.py` + `infra/coverage_repository.py` — the cell model
    (see §5 cell identity) with `mark_seen` / `unknown_cells` / `summary`,
    persisted in SQLite
  - `infra/report.py` — `build_m5_report` + heatmap render
  - `cli/campaign.py` — session lifecycle (list/create/show/status/start/
    abort/archive) *for manually-authorable* campaigns
- **Frozen plans + leases + janitor + exit codes** make it CI-safe today
  (`cli/exit_codes.py`, 0.5.1 "janitor reclaims crashed controllers' leases").

### What is weak / unfinished (gaps this plan must respect)

- M5 candidate machinery is **not reachable from regular usage**: no command
  generates candidates from a live topology, runs them through the gates, and
  records coverage. `campaign run` iterates a list of authored drill specs
  (`cli/campaign.py`); the generator/campaign-engine/coverage pieces are
  exercised mostly by tests.
- **CLI surface is broad and internally consistent but not workflow-shaped**:
  14 top-level commands; there is no single "what should I do next" entry
  point, no readiness preflight, no init, no explain.
- **Coverage is a concept with tables but no user-facing home** (no
  `mayhem coverage`, no "what's untested", no `mayhem next`), and the existing
  `mark_seen` accounting has no notion of *evidence quality* — an exec
  cell is currently treated as one bit regardless of whether it was proved,
  inconclusive, or failed. **Drift (C17, 2026-09-10):** the working tree's
  M5-2 coverage upgrade (feat-2/feat-3 scope) already supersedes the "one bit"
  framing — `domain/coverage.py` carries a 5-state `CellState` model +
  `transition()`, and `infra/coverage_repository.py` + migration 12 persist
  `state` / `blocked_reason` / `verdict_json`. This bullet predates that work;
  see `docs/grounding-log.md` claim C17.
- **Doc/CLI drift exists** (re-design.md §24): stale refs, dead command
  examples, non-migrated ad-hoc tables (`tracked_resources`,
  `mutation_journal`), fake `--host` on toolkit probing, unwired JSON. Ruff is
  deliberately not a hard gate.
- **Kubernetes is interface-only** (`domain/k8s_adapter.py`, refusal gate
  `k8s.unsupported`; `examples/k8s/README.md`) — by design, M8 not done.

---
## 2. Personas (who we build for)

| Persona | Goals | Pain today |
|---|---|---|
| **Solo operator (primary; [interview])** | Get a verdict on "does my stack recover", fast, and trust it; not re-learn the CLI every month | Must write a drill by hand before first run; 14 commands; no guidance on *what* to test next; failure debugging is manual (`docker inspect` by hand) |
| **CI pipeline (secondary)** | A gate: run chaos, get exit code + evidence artifact, don't flake | Works today, but no min-coverage gate, no JUnit-style output, no trend |
| **SRE on a small team (aspirational)** | Cover a composed stack systematically; compare before/after a deploy | No coverage map, no baseline/compare, no session-level report |

**Design rule:** every 0.6 feature must work for the solo operator with zero
authored configuration *and* deepen automatically as they author more.

---
