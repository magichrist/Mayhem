# Changelog

All notable changes to this project will be documented in this file.

This changelog is generated from the project's git history by
[git-cliff](https://git-cliff.org). Mayhem commits are grouped both by the
**drill phase** that produced them (Explore / Expert / Coverage / Next) and
by conventional-commit type — see the phase map below.

## [unreleased]

### 📚 Documentation

- Add v0.9.0 roadmap and implementation plans

- Establish the v0.9.0 release truth baseline: checked command inventory, install
  dependency contract, version metadata, and Justfile recipe paths


## 1.0.0 - 2026-09-29

### ⚠ Breaking changes

- **`db.slow_query` now defaults to `mode: latency` (netem).** It previously
  shipped an `iptables DROP` as its default behaviour, so a plan that relied on
  the default was silently injecting packet loss rather than latency. The
  blackhole behaviour is still available, but it must now be asked for
  explicitly with `mode: timeout`. Existing specs that want a drop must add the
  parameter; existing specs that want latency are now correct by default for the
  first time.
- **Nine `catalog_only` entries are new refusals** (thirteen in the catalog
  today). These fault ids parse, plan, and refuse before mutation instead of
  reaching an executor. A plan that names one is now rejected at compile time;
  a plan that ran under 0.9.x will not run now. The refusal text names the
  mechanism mayhem does not have and points at a documented alternative — the
  refusal is the deliverable, not a placeholder.
- **`mayhem p` no longer resolves.** The `pack` command made the `p` prefix
  ambiguous, so a bare `mayhem p` invocation now exits `ambiguous_command`
  (exit code 10) and names both candidates. Scripts using the `p` prefix must
  move to `mayhem pre` or `mayhem prep` (both resolve to `prepare`), or spell
  the command out in full.
- **`blast_radius.forbidden_fault_pairs` now actually fires.** It was silently
  inert: the check compared a `frozenset` of *all* faults seen so far against
  two-element forbidden pairs, so it matched on a two-fault plan by accident and
  matched nothing on any plan of three or more faults. It is now evaluated
  against each `{earlier, new}` pair, which makes it complete — a plan
  containing a forbidden pair is refused no matter where the pair sits in the
  ordering. **This is the most important item in this release: a safety rule
  that used to be decorative is now load-bearing, and plans that ran under
  0.9.x may now be refused.** A safety setting you configured and believed was
  protecting you was not.
- **`blast_radius.damage_quota` is a new cumulative gate.** The five existing
  `blast_radius` limits are per-step. `damage_quota` is the first budget that
  sees the *sequence*: it charges damage-seconds per target across the whole
  plan and refuses when the cumulative total exceeds `budget_s`, or when any one
  target's total exceeds `per_fault_ceiling_s`, within `window_s`. A plan whose
  every individual step passes the other five limits can now still be refused
  for its total. It is active by default (14400 s budget, 3600 s per-fault
  ceiling, 7-day window) rather than opt-in.

### 📚 Documentation

- State plainly in the README that mayhem has **no kernel/BPF fault injection**,
  and name the thirteen `catalog_only` faults and the mechanism each one lacks.
- State that **0 of 141** catalog faults are `verified-live`, and that
  `verified-unit` is a claim about mayhem's own parameter, refusal, and
  compensation code rather than evidence that a fault works.
- Correct the two places the documentation called a fault pack *signed*. The
  pack format declares a `signature: str` with no key, no algorithm, and no
  trust store; a loader now enforces a SHA-256 *integrity* digest and reports
  `signature NOT VERIFIED`. Authorship is an unverified claim.
- Add intra-document **anchor** validation. The documentation-consistency test
  validated link *paths* only, so a Markdown link with a bare `#fragment`
  target was invisible to it and a dangling anchor shipped unnoticed.
- Correct the README claim that `max_faults` caps simultaneous faults. No gate
  reads it; `blast_radius.max_concurrent_faults` is the control that refuses.
- Document `blast_radius.damage_quota` in the configuration reference.

### 🛡 Fixed

- `blast_radius.forbidden_fault_pairs` now evaluates each `{earlier, new}` pair
  instead of the set of all faults so far (see the breaking change above).

### 📦 Documentation index

- The 1.0.0 section above is **hand-written** because the breaking changes are
  not derivable from commit subjects. `git-cliff` regenerates this file from
  git history and will not reproduce it; re-add the section after any
  regeneration.


## 0.8.0 - 2026-09-25



### 🚀 Features

- Kubernetes targeting system

- Refined target.py

- Kube topology structure

- Kube topology for cli

- **k8s**: K-plan-3 container-level signal execution

- Update executors.py

- Update k8s_resolve.py

- Update lease_client.py

- Update campaign.py

- Update lifecycle.py

- Update services.py

- Update config.py

- Update cell_runner.py

- Update executor.py

- Update k8s_runtime.py

- Update safety.py

- Update leases.py

- Update resolution.py

- Update lease_repository.py

- Extend executor agents with K8s runtime support

- Add K8s control plane agent

- Update CLI app for K8s executor integration

- Update coverage command for K8s runtime

- Update explore command for K8s runtime

- Update next command for K8s runtime

- Update services command for K8s runtime

- Update toolkit for K8s runtime

- Update topology for K8s runtime

- Update controller executor for K8s runtime

- Extend K8s runtime with execution support

- Extend fault catalog with K8s faults

- Update K8s example spec

- Update executor agents

- Update dependencies for K8s runtime

- Update K8s control agent

- Update lifecycle CLI for K8s

- Update services CLI for K8s

- Update K8s runtime controller

- Update planner for K8s runtime

- Extend fault catalog

- Update common domain for K8s

- Add K8s adapter domain

- Update maniac domain for K8s

- Add runtime adapter for K8s

- Update target selector for K8s

- Add K8s manifest topology provider

- Add policy, evidence, provider, and schema foundations

- Expand agent and controller execution flows

- Expand CLI commands and output handling

- Finalize active CLI workflow surface



### 🐛 Bug Fixes

- Release.yml

- Initialize slotted CLI exceptions safely



### 💼 Other

- Update docs/adr-adr-m7-1-k8s-executor-flip.md

- Delete docs/features.md

- Delete docs/k-plan-1.md



### 🚜 Refactor

- Format and ruff-fix



### 📚 Documentation

- Enhance readme file, removed dev version stuff

- Kubernetes plans/spec/adrs

- Update README.md

- Update adr-m7-1-k8s-executor.md

- Update config.md

- Update drill-spec.md

- Remove k-plan-2.md

- Remove k-plan-3-implementation-subplans.md

- Remove k-plan-3-sub-plans-k8s-executor-flip.md

- Remove k-plan-3-sub-plans.md

- Remove k-plan-3.md

- Remove k-plan-4-sub-plans.md

- Remove k-plan-4.md

- Remove k-plan-5.md

- Add k8s-plan-1.md

- Add k8s-plan-2.md

- Update architecture and reference documentation

- Clarify the default installation bundle



### 🎨 Styling

- Remove obsolete noqa suppressions



### 🧪 Testing

- Add tests for kube

- Update test_kplan3_runtime.py

- Update test_m7_k8s.py

- Update test_safety.py

- Add test_kplan5_runtime.py

- Update CLI tests for K8s runtime

- Update container fault matrix tests for K8s

- Update example specs YAML tests for K8s

- Update fault catalog tests for K8s faults

- Update K8s plan-3 runtime tests

- Update K8s plan-5 runtime tests

- Add K8s plan-6 runtime tests

- Update CLI tests for K8s runtime

- Update K8s plan-6 runtime tests

- Add K8s manifest topology tests

- Expand runtime, CLI, provider, and policy coverage

- Add exhaustive CLI and runtime coverage

- Pin compose topology discovery runtime



### ⚙️ Miscellaneous Tasks

- Update development tooling and package metadata

- Add provider and container examples

- **release**: Bundle Kubernetes and parallelize unit tests

- Remove broken architecture gate from release


## 0.6.2 - 2026-09-11



### 🐛 Bug Fixes

- ApiVersion was not added to tests


## 0.6.0 - 2026-09-11



### 🚀 Features

- Plan for 0.6.0



### 📚 Documentation

- **feat-1**: Ground every §1 claim in a verification log + persona design rules

- New features dictation



### 🧪 Testing

- Verify config absorption, CLI contract, coverage, KPI + ranking


## 0.5.1 - 2026-09-09



### 🚀 Features

- Add example experiment definitions (maniac-hour, proc-pause-drill)

- Add net.load fault

- Add color logs, better readability, also fix some bugs

- Add execution to agents

- Topology service is better now

- Lease now have more capabilities

- Adrs and milestones are mostly done

- Kube and other adrs applied

- Add M0011 migration for M5 run and outcome tables

- Add Run/Outcome persistence methods to Store

- Add M0012 migration for M5 coverage table

- Add candidates module

- Add coverage module

- Add m5_campaign module

- Add run_outcome module

- Add campaign_engine module

- Add candidate_gates module

- Add candidate_generator module

- Add coverage_repository module

- Add maniac module

- Add report module

- Add new faults and better tested campaign+runner

- **resilience**: Attach end-of-run resilience score + diagnosis to drill runs

- **dependency**: Add 'mayhem dependency compile' to bake fault tooling into compose

- **janitor**: Finalize ORPHANED/RELEASING and surrender stale DIRTY leases

- **lifecycle**: TTL-sweep sticky leases before every run

- **examples**: Add net.load fault to the testCase api drill

- **resilience**: Grade bands and grounded metric table in the report

- **cli**: Maniac zero-config synthesis and --ctr container scoping



### 🐛 Bug Fixes

- **faults**: Better handling

- **app**: Fix known issues in app arch

- Minor change

- Executor is now behaving right

- Config old syntax removed, updated DSL

- Maniac cli now works as it should

- **impact**: Gate every in-container fault on its real tooling

- Net.load uses localhost if container exposes port else must gain ip

- **leases**: DIRTY is not terminal — may only be surrendered to EXPIRED

- **executor**: Resume orphan recovery from any checkpoint state

- **compensation**: Clock.skew inject must double-quote $target expansion

- **impact**: Gate SYS_TIME faults as inert under rootless engines

- **dependency**: Warn when bootstrapped service relies on image CMD only

- **examples**: Give testcase-lb an explicit command

- Clock.skew and process.stop are fixed, also add failure policy: fast-fail, continue

- **faults**: Accept numeric seconds for DURATION params

- **topology**: Container resolves as running when state inspect fails

- **janitor**: Reclaim crashed controllers' leases before TTL



### 💼 Other

- Init

- Init

- Add more bugs

- Updated README

- Near release

- Add more bugs

- 0.2.0dev

- Update executors module

- Update compensation module

- Update catalog module

- Update faults module

- Remove cached .pyc file

- Update agent_protocol tests

- Update executor tests

- Update README

- Remove answer2 doc

- Update drill-spec doc

- Remove milestones docs

- Remove plan-drill-spec doc

- Remove runtime-adapters plan doc

- Update executors module

- Update impact module

- Update probes module

- Update compensation module

- Update executor controller module

- Update planner module

- Update resource_manager module

- Update safety module

- Update capabilities module

- Update catalog module

- Update common module

- Update events module

- Update execution_context module

- Update execution_loci module

- Update experiments module

- Update faults module

- Update k8s_adapter module

- Update topology module

- Update migrations module

- Update migrator module

- Update report module

- Update store module

- Update adapter_registry module

- Update docker_adapter module

- Update topology service module

- Update m5 e2e tests

- Update agents tests

- Update cancellation tests

- Update compensation tests

- Update coverage tests

- Update drill_spec tests

- Update executor tests

- Update faults tests

- Update maniac tests

- Update report tests

- Update run_outcome tests

- Update topology_providers tests

- Add MS-Complete doc

- Add ADR-M4-3 success criteria

- Add ADR-M4-4 observability

- Add observability_collector module

- Add decisions module

- Add observability module

- Add success module

- Add m7 k8s tests

- Add m8 operations tests

- Add observability tests

- Add success tests

- Rewrite README: drill-engine positioning, comparison table, run transcript walkthrough, quickstart

- Expand example drill: recovery off, check_spec, success criteria, observability sources, container.restart/pause faults

- Print copy-paste run handle with mayhem history command after run

- Pass spec_dir into plan_drill so relative asset paths resolve against the drill file

- Materialize user-supplied k6 script content into container instead of inline GET script

- False keeps fault in place, releases lease terminally as kept_faulted without dirty flag

- Embed net.load script content into frozen plan and propagate recovery flag per fault

- Add net.load script param for custom k6 script.js path

- Add recovery flag to DrillConfig, DrillFault override, and PlannedFault

- Emit ProcessNode with main PID so process-addressed faults resolve, matching docker provider

- Assert run output includes the mayhem history copy-paste handle

- Update README

- Remove MS-Complete.md

- Remove deprecated ADR documents

- Update drill spec documentation

- Update agents executors

- Update CLI app

- Update CLI lifecycle

- Update CLI services

- Update config

- Update controller compensation

- Update controller planner

- Update domain catalog

- Update domain decisions

- Update domain experiments

- Update unit test CLI

- Update unit test maniac

- Ongoing pypi release🎊



### 🚜 Refactor

- Rename package tgondi to mayhem

- Ruff format



### 📚 Documentation

- Update documentation for mayhem rename and add re-design/rename notes

- Removed old docs, new arch plan in next commit

- Document recovery control and net.load script param in drill spec



### 🎨 Styling

- Reformat threshold type-check conditional in probes.py



### 🧪 Testing

- Update and add tests for renamed mayhem package

- **e2e**: Automated e2e tests with justfile

- **e2e**: Fixed some errors

- **e2e**: All tests pass 🎉

- **unit**: Near pass

- Add M5 campaign semantics and execution loop tests

- Add m5 e2e integration tests

- Add candidates unit tests

- Add coverage unit tests

- Add maniac unit tests

- Add report unit tests

- Add run_outcome unit tests

- Test net.load user k6 script content embedding in inject argv

- Test recovery flag defaults and per-fault override in DrillSpec

- Test recovery:false keeps process stopped with kept_faulted lease and skipped undo

- Test net.load script embedding against spec_dir and recovery propagation to plan

- Add container x fault matrix and fix stale config-show e2e assertion

- **leases**: DIRTY surrender-only and janitor-only EXPIRED transition

- **domain**: DIRTY may transition to EXPIRED in the leak-property table

- **janitor**: Stale DIRTY surrendered, ORPHANED/RELEASING finalized

- **compensation**: Clock.skew full-script expansion regression

- **impact**: Rootless detection + SYS_TIME inert gating

- **e2e**: Compile warns on program-less service, silent when command declared



### ⚙️ Miscellaneous Tasks

- Update gitignore for mayhem rename and local artifacts

- **examples**: Commit compiled docker-compose.mayhem.yml for testCase

<!-- generated by git-cliff -->
