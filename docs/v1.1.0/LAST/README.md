# LAST — the four seams that are built but unwired

Status: **all four implemented, 3 of 3 phases each.** Per-file `## STATUS`
blocks are authoritative. Created after reading all ~~24~~ **31** `## STATUS`
blocks in `docs/v1.1.0/` (25 of them on feature plans, 6 on meta documents) and
verifying every claim against `src/mayhem/`. Research date
**2026-10-18**. *(The count this line first carried, 24, was stale; corrected
against `grep -l "^## STATUS" docs/v1.1.0/*.md`.)*

## What this package is, and is not

The v1.1.0 program reports ~~22 of 24~~ **23 of 25** plans at 6 of 6 phases.
*(Corrected — the counts this sentence first carried were written when fewer
plans existed; the plan set is now the 25 feature plans (01–23, 29, 30) and each
plan's own `Overall:` line is the arithmetic, enforced by
`tests/unit/test_plan_doc_status_blocks.py`.)* The two that do not
(`02_KUBERNETES_RUNTIME.md`, `20_ENTERPRISE_PRODUCT_HARDENING.md`) are PARTIAL on
**live** acceptances: a Kubernetes cluster, an IdP, a human approver, a container
runtime. Those three items are not in this package, and no amount of code closes
them.

This package is the **other** set of open items — the ones a unit test can reach
and that no infrastructure unblocks. Each is a seam where a real, tested,
production-shaped function exists and has **zero production callers**. They were
found by grep, not by reading prose, and each is confirmed by a `## STATUS` block
that names the same gap.

| File | Seam (as it was) | Owner cited by | Result |
| ---- | ---- | ------------- | ------ |
| [L1_DOC_HONESTY.md](L1_DOC_HONESTY.md) | Four plan documents still said `planning only, 0%` | `24`, `25`, `26`, `28` | DONE — 6 prose lines + 22 tests |
| [L2_RUN_CLOSE_AUTHORIZATION.md](L2_RUN_CLOSE_AUTHORIZATION.md) | `seal_policy_decision` had no caller; every mutating run sealed an INCOMPLETE chain | plan 12 | DONE — 29 tests |
| [L3_RELEASE_GATE_CALLER.md](L3_RELEASE_GATE_CALLER.md) | `release_gate()` had no caller in `src/` at all | plan 22 | DONE — 34 tests |
| [L4_GATE_ATTACHMENT.md](L4_GATE_ATTACHMENT.md) | The gate/budget **binding machinery had zero tests and zero documentation**, and two ledgers falsely claimed the call sites did not exist | plan 10, plan 23 | DONE — 41 tests |

> **Correction carried into this index.** An earlier reading reported that
> `attach_preflight_gate` and `attach_resource_budget` have no production call
> sites. They do — `cli/lifecycle.py` calls `run_gate()` and `run_budget_guard()`
> and passes both to `engine_for` at four sites. L4 was rewritten around what is
> actually true, and the correction is recorded in that file's own STATUS block
> rather than deleted. Implementing L4 also surfaced four *source* docstrings
> naming a function called `build_run_engine`, which exists nowhere in the tree;
> those were renamed to `engine_for`.

Sequencing: **L1 → L2 → L3 → L4.** L1 is first because it is hours and it restores
the doc-honesty contract the rest of this package depends on being able to claim.
L2 and L3 both land on the run-close path; L2 first because it is the larger
correctness gap. The four are otherwise independent — no one blocks another.

## Phase convention

The program uses six phases per feature plan (1 domain, 2 engine, 3 surface,
4 safety/evidence, 5 tests, 6 docs/rollout). These four items are smaller than a
feature lane, so each compresses to three:

1. **The seam** — the type, contract, or rule, with zero IO and no caller.
2. **The wiring** — the production call site and the surface that shows it.
3. **The proof** — tests with negative controls, the honesty gate, the ledger.

Phases are ordered by dependency, not by effort. A phase is not DONE because its
code landed; it is DONE when its Phase 3 gate passes.

## The rules every phase below obeys

These are the conventions `docs/v1.1.0/README.md` §"Conventions every feature
plan follows" already states. They are repeated because each plan below can violate
them by accident.

1. **Additive.** A default of `None`/`()` leaves every existing path
   byte-identical. A golden test proves it before the change, not after.
2. **Fail closed.** An unwired seam stays fail-closed and says so. Turning a
   silent pass into a refusal is allowed; turning a refusal into a silent pass is
   not.
3. **Evidence before prose.** Every behaviour ships with the test that proves it,
   *including* a negative control wherever a check could be decoration.
4. **Honesty is a gate.** The plan document is parsed by a test, the counts are
   cross-checked against the `DONE` lines, and each checker is mutation-tested
   against a deliberately broken copy of the document.
5. **One answer.** No second planner, no second sealer, no second gate. Each plan
   below names the existing function it delegates to.

## What this package does not claim

* It does not close `certified_faults = 0`. That needs live cells (plan 01).
* It does not produce `verified-live` for eBPF (04), probes (11), cloud (06),
  Terraform (16) or soak (23). Those need real infrastructure.
* It does not implement KMS/HSM, Sigstore/Cosign, WORM storage, X.509, or a
  quorum epoch witness. Those are named unimplemented in their own plans and
  stay that way.
* It does not touch `docs/v1.1.0/24_RELEASE_GATES.md`'s *enforcement* half. L3
  gives `release_gate()` its first caller; making the full gate suite green for a
  production-class release is plan 24's Phase 6 and needs a soak.

## Verification

No container runtime, no cluster, no network, no new dependency. Every phase was
discharged with `pytest -n 3` over a named subset:

```bash
# L1
uv run pytest -n 3 tests/unit/test_plan_doc_status_blocks.py tests/unit/test_last_l1_plan_docs.py
# L2
uv run pytest -n 3 tests/unit/test_policy_gate.py tests/unit/test_preflight.py \
  tests/unit/test_run_close_authorization.py tests/unit/test_last_l2_plan_docs.py \
  tests/unit/test_evidence_boundary.py
# L3
uv run pytest -n 3 tests/unit/test_comparison.py tests/unit/test_coverage_service.py \
  tests/unit/test_check_gate.py tests/unit/test_release_gate_cli.py tests/unit/test_last_l3_plan_docs.py
# L4
uv run pytest -n 3 tests/unit/test_binding_spec.py tests/unit/test_cli_doctor.py \
  tests/unit/test_last_l4_plan_docs.py tests/unit/test_readme_honesty.py
```

Plus `ruff check`, `ruff format --check`, `mypy` on the touched files, and
`lint-imports`, whose layering contract (`controller ← agents ← toolkit|infra ←
domain`) passes.