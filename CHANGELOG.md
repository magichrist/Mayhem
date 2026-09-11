# Changelog

All notable changes to this project will be documented in this file.

This changelog is generated from the project's git history by
[git-cliff](https://git-cliff.org). Mayhem commits are grouped both by the
**drill phase** that produced them (Explore / Expert / Coverage / Next) and
by conventional-commit type — see the phase map below.

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
