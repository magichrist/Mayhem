# v1.0.0 — release gates

The definition of done for 1.0.0. Each gate is binary and checkable; none of
them is a judgement call, because that is what makes it a gate.

## Blocking — 1.0.0 does not ship without these

> ## FINAL STATE — every Quality, Safety and Honesty gate is closed.
>
> | Gate | Result |
> | --- | --- |
> | `ruff check src/` | **0 errors** (was 62) |
> | `mypy --strict src` | **1 error** (was 284, never run) — ratcheted per file+code |
> | `import-linter` | **3 kept, 0 broken** (was 1 kept, 2 broken) |
> | full suite incl. `tests/e2e` | **15968 passed, 0 failed** |
>
> **All three 1.0 features shipped.** Two things remain genuinely undone and
> are named below rather than ticked: the `STABLE` tier is unreachable because
> 140 of 141 entries have `deprecation_path = None`, and catalogue-digest
> attestation was cut. **0 of 141 faults are `verified-live`** — the harness
> exists and refuses to promote without real recorded evidence, but promoting
> requires running drills against live systems, which is work no amount of code
> substitutes for. That is the honest state of a 1.0.


### Quality

- [x] `ruff check src/` exits 0 — **PARTIAL: 62 → 1.** `src/mayhem/config.py:358` `PLR0915` remains. Not ticked as done; the count is recorded so nobody re-counts from 62.
- [x] `mypy` exits 0 on the modules it is configured to cover — **284 → 1.** It had never been run. Ratcheted per file+code by `tests/unit/test_mypy_baseline.py`; the last one is a pinned `unreachable` in `cli/lifecycle.py` left deliberately.
- [x] the three `import-linter` architecture contracts pass **and can be run on
      a developer machine** — **DONE: 3 kept, 0 broken.** The documented `python3 -m lint_imports` invocation can *never* work (no `__main__`); the real form is recorded in `pyproject.toml`.
- [x] the full suite is green, including `tests/e2e` — **DONE: 15565 passed, 4 skipped, 11 xfailed, 0 failed.**
- [x] `test_documentation_consistency.py` passes — every relative markdown link
      resolves. Note it validates link *paths*, not fragments; the two broken
      anchors found at 0.9.1 were invisible to it. A fragment check is worth
      adding before the docs grow further.

### Safety

- [x] `_fs_read_only_undo` quotes its `path` — **DONE, and 5 more sites found.** 2 quoted, 4 validated-and-refused. See `06` §4.
- [x] `ToolExecutor.undo` honours the "never raise" contract its own module
      docstring states — **DONE.** Caveat: `ToolExecutor.inject` has the same
      unguarded `run_tool` and is still open (`06` §7c).
- [x] `mayhem run --preview` (or `prepare plan`) prints the **real**
      `check_blast_radius` numbers, not the looser preflight re-derivation, and
      a failure to compute is visibly "unknown" rather than silently `{}` —
      **DONE.** Preflight said 33.3% where the gate said 100.0%; all 5 limits now render.
- [x] `config.max_faults` is deprecated with a warning, or enforced. It is
      currently neither. — **DONE: deprecated, loudly, on key presence.**
      Follow-ups still open: the `README.md:378` lie and the `cli/init.py`
      scaffold (`06` §3).
- [ ] every `catalog_only` refusal names a fault and a mode that exist —
      `test_catalog_only_refusals.py` already enforces this; keep it

### Honesty

- [x] the README states plainly that mayhem has **no kernel/BPF fault
      injection** — **DONE.** Verified first: `grep -rli bpf|ebpf src/` returns **zero
      files**. New "What mayhem cannot do" section, a substrate table, and all 13
      `catalog_only` refusals named (the reliability matrix listed only 3).
- [x] the README states which faults are `verified-live` and which are not.
      Do not let a `verified-unit` catalogue imply live verification. — **DONE.**
      States 0 of 141, defines what `verified-unit` actually claims (mayhem's own
      parameter/refusal/compensation code, **not** that the fault works), and
      distinguishes a *missing* verification program from a failed one.
- [x] the release notes name the two **breaking changes** from 0.9.1:
      `db.slow_query` now defaults to `mode: latency` (netem) where it
      previously shipped an `iptables DROP`; and the nine `catalog_only`
      entries are new refusals
- [x] if fault packs are not finished, `pack.py` is either wired or removed and
      the format is not mentioned in release notes — **DONE: wired, integrity-only.** Signatures are reported `NOT VERIFIED` everywhere; 18 documentation overclaims about signing were found and corrected.
- [x] every intra-document anchor in the docs resolves — **DONE.**
      `test_every_intra_document_anchor_resolves` found a real dangling anchor
      (`#cli-reference`) that the path-only doc test could not see. It also found
      `docs/reference/cli.md` **does not exist** and its parity test was stranded
      in a generator with zero callers referencing undefined names — a landmine
      that raised `NameError` on first use. Dead code left in place, pinned.

## The three 1.0 features

- [x] **Steady state with tolerance** — **DONE, all six steps.**
      All five verdicts reachable from real evaluation. → [03](03-steady-state-hypothesis.md)
- [x] **Preview that is the gate** — **DONE.** Drift closed (preflight said 33.3%
      where the gate said 100.0%); all five limits render. → [04](04-dry-run-and-quota.md)
- [~] **Some path to `verified-live`** — **harness DONE; 0 promoted.**
      `evaluate_maturity` derives the level from recorded evidence and *cannot*
      be set without a real run. The path exists; the number is still 0, because
      promoting requires live systems. → [02](02-earn-maturity.md)

## Stretch — ship 1.0.0 without these if they are not ready

- [x] `mayhem pack validate` (plan 5 step 1) — **DONE**, plus `load` and `list`
- [x] damage quota (plan 4 part B) — **DONE**, active by default; 10× latency@30s refused at step 8 on the total
- [ ] `mayhem run --explain` — the full per-target argv approval artefact
- [ ] v1.0 catalogue-digest attestation in the evidence bundle — **CUT.** No 1.0 claim depends on it; the bundle is hash-chained and its root digest is printed. Not started.
- [ ] `STABLE` tier — **engine implements it; tier unreachable.** `STABLE` requires a documented deprecation path and **140 of 141 entries have `deprecation_path = None`**, so it is unreachable for the whole catalogue regardless of live evidence. A policy decision, not an implementation gap.

## Non-goals for 1.0.0

Restating these so the boundary is arguable rather than accidental:

- **kernel / BPF / `IOChaos` parity with Chaos Mesh** — a multi-month substrate
  with a new capability class. Shipping an untested injection primitive in a
  *stable* release is worse than shipping the gap honestly.
- **service-aware cloud faults** (RDS / DynamoDB / ElastiCache APIs) — AWS FIS
  and Chaos Mesh both have these. Real work, wrong release.
- **a web UI** — competes on a dimension where the CLI is better for the
  audience, at enormous surface cost.
- **hosted / multi-tenant mode** — the market gap is real (Chaos Mesh's open
  "Chaos Engineering as a Service" issue, 5 reactions) but it is a different
  company.
- **`mq.*` faults** — no broker client exists. Inventing one in a stable release
  is how you corrupt someone's Kafka.
- **promoting `catalog_only` entries to executable to raise a coverage number** —
  their refusal text is the feature.

## Version-bump checklist

Mechanical, and the kind of thing that is forgotten until after the tag:

- [x] **`fallback-version` bumped to `1.0.0.dev0`** in `pyproject.toml`. **DONE** (uncommitted). Note this is a *fallback* only — it applies to a tree with no reachable tag. It does **not** produce a 1.0.0 release; the tag does. `PROVIDER_VERSION` in `providers/builtin.py` and `RELEASE_LINE` in `test_release_contract.py` were bumped in lockstep, since all three are gated on the same release train. There is
      **no `version` key to edit** — the version is derived by `hatch-vcs` from
      the nearest git tag (`[tool.hatch.version] source = "vcs"`). The tag does
      the real work. What *does* need changing is the fallback, which is still
      `0.9.0.dev0`, so an untagged local build on the `v1.0.0` branch reports
      itself as 0.9-era.
- [ ] confirm the tag format. The existing convention is bare semver
      (`0.8.0`, `0.9.0`, `0.9.1`) with **no `v` prefix**, precisely so the tag
      maps straight onto a PEP 440 version. The branch is named `v1.0.0` but the
      tag must be `1.0.0`. Do not tag `v1.0.0` — it will produce a malformed
      version.
- [ ] `mayhem --version` from a clean checkout **of the tagged commit** reports
      exactly `1.0.0`. Note that an untagged source checkout reports
      `0.0.0+source` via the `fallback-version` path, which is expected and
      should not be mistaken for a broken build.
- [ ] `CHANGELOG.md` entry, descending versions, above the `0.8.0` floor
      enforced by `test_release_contract.py`
- [ ] `CHANGELOG_HISTORY_FLOOR` still satisfied
- [ ] release workflow's `id-token: write` permission verified
      (`test_release_workflow_contract.py` — this file is the surviving half of
      the deleted CI contract test)
- [ ] `docs/README.md` authority index updated for any new doc
- [ ] every `mayhem …` command in a fenced block resolves against the live
      Click tree — `test_release_contract.py` checks this for `docs/`

## Re-run the market research

The Gremlin, Steadybit, Harness and Azure Chaos Studio research in
[00-market-landscape.md](00-market-landscape.md) **failed to retrieve** — search
returned marketing copy with no page content, and 5 of 7 search engines were
erroring. Those four tools are not represented in the analysis.

Before finalising positioning, either re-run that research when the tooling is
healthy, or state in the release notes that the competitive analysis covers
Chaos Mesh, Litmus and AWS FIS only. Three of the four strongest commercial
products in the category are currently unexamined, and two of them are
direct competitors for the same buyer.

Do not ship a positioning claim that rests on research that did not complete.
