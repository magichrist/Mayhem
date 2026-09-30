# 08 — the `withdrawal` audit

**Lane I, v1.0.0 plan 06 §6.** Spec read: `06-debt-and-quality.md:254` — *"## 6.
`withdrawal` audit — the one asset with no plan"*, tracked as untouched at
`docs/v1.0.0/README.md:136`.

**Provenance note before anything else.** Git is off-limits for this lane, so
every statement below is reconstructed from the working tree — source, docstrings,
`docs/`, `CHANGELOG.md`, `tests/`, and the live CLI. I did not read `.git/` and
did not run a single git command. Where history would normally settle a question
(who added what, when, and why), the tree is silent and I say so rather than
guessing. The limits of that evidence are collected in §5.

---

## 1. Verdict

**`withdrawal` does not exist. It is a phantom asset — a name in a heading with
no referent anywhere in the repository.**

The brief I was handed asserted that `withdrawal` is a chaos-engineering method
*and* a mayhem asset with a `deprecation_path` in the fault catalogue. Both
halves are false. The string appears **twice in the entire working tree**, and
both occurrences are the planning documents naming each other:

```
$ grep -rniI "withdraw" . --exclude-dir=.git --exclude-dir=.venv --exclude-dir=node_modules
./docs/v1.0.0/README.md:136:| [06 §6](06-debt-and-quality.md) | untouched — the `withdrawal` audit |
./docs/v1.0.0/06-debt-and-quality.md:254:## 6. `withdrawal` audit — the one asset with no plan
```

There is no source file, no test, no doc page, no fault id, no command, no
workflow name, no capability, and no changelog entry. The audit therefore has
two halves: **§2–§3** dispose of the named asset, and **§4** audits the section
that the heading *actually* describes — because a plan section whose title and
body are about different things is itself the finding, and what its body is about
has a real, live, shipping defect.

---

## 2. What exists

### 2.1 Not a workflow / run mode / script

`src/mayhem/cli/command_registry.py:37-59` is the closed command surface
(`COMMAND_SPECS`, 18 groups). `src/mayhem/cli/workflows.py:26,95,106` defines
the discover/prepare/extend groups. `tests/unit/test_command_registry.py:16-18`
pins the workflow vocabulary to a closed set of seven:

```python
assert workflows <= {"discover", "prepare", "experiment", "run", "inspect", "recover", "extend"}
```

`withdrawal` is not a member. There is no `campaign mode`, no `drill mode`, and
no run mode by that name: `FaultCategory` (`src/mayhem/domain/faults.py:23-41`)
has 18 members, none of them `withdrawal`.

### 2.2 Not a documented method

No `SKILL.md` in the repository. `docs/` contains `README.md`,
`compensation.md`, `config.md`, `drill-spec.md`, `fault-catalog/`, `new-faults/`
and `v1.0.0/`. The documentation-authority index (`docs/README.md:29-52`)
enumerates every tracked document and classifies it; nothing in it is a
`withdrawal` method, and nothing anywhere in `docs/` describes a chaos-week
practice. Grepping for the method's actual vocabulary — `jepsen`, `chaos week`,
`chaos-week`, `chaos_week` — returns **zero hits** in `src/`, `docs/`, and
`README.md`.

### 2.3 Not dead code, and not a declared capability

It is not dead code, because there is no code. Nor is it a declared-but-
undispatched capability:

- **Fault catalogue.** `all_definitions()` returns **141** definitions. None
  contains `withdraw`. Every id is a `<category>.<name>` pair from
  `_PREFIX_TO_CATEGORY` (`src/mayhem/domain/faults.py:57-79`); no prefix
  resolves to anything of that shape.
- **`deprecation_path`.** Exactly **2** of 141 definitions carry one, both
  hard-coded in `_define` (`src/mayhem/domain/catalog.py:206-216`):
  `k8s.image_pull_slow` ("Keep catalog-only until a registry-pacing runtime
  exists…") and `k8s.nvidia_smi_error` ("Retire on clusters without NVIDIA
  device-plugin support…"). Neither is `withdrawal`, and neither is the
  "chaos-week" method the brief described.
- **`catalog_only` refusals.** **13** definitions, listed in full at
  `src/mayhem/agents/impact.py:176-191` (`app.deadlock`, `app.exception`,
  `clock.freeze`, `cpu.interrupt_storm`, `cpu.steal`,
  `dependency.malformed_response`, `fs.permission_failure`, `fs.read_error`,
  `mem.fragment`, `mem.oom_kill`, `process.oom_kill`, `process.startup_delay`,
  plus `k8s.image_pull_slow`). This *is* the real "declared but refused" surface
  in mayhem — and it is already documented and gated: `README.md:585` states
  "13, all refused before mutation", `docs/README.md` defines the
  "Catalog-only fault" state, and plan 07 gates on "every `catalog_only`
  refusal names a fault and a mode that exist"
  (`docs/v1.0.0/07-release-gates.md:41`); `docs/README.md:73` records "Thirteen
  today".

So the honest classification of the named asset is not "declared-but-absent".
It is **absent, with no declaration** — a heading.

### 2.4 Reachability, proved both ways

Not reachable. Proof is enumeration, not inference — I walked the live click
tree rather than reading source and hoping:

```
$ .venv/bin/python -   # walks app.commands recursively
90 commands reachable
... bundle / bundle show / bundle verify / campaign / campaign abort / ...
WITHDRAWAL HITS: []
```

90 dispatchable command and subcommand paths; zero contain `withdraw`.
Corroborated by the static surface: `COMMAND_SPECS` (18 groups) and
`ACTIVE_COMMANDS` in `tests/unit/test_cli_active_surface.py:8-27`.

### 2.5 Guard added

`tests/unit/test_withdrawal_asset.py` — 4 tests, ruff-clean. It pins: no
dispatchable path contains `withdraw`; no catalogued fault id contains
`withdraw`; the `bundle` group's subcommand set; and that `build_bundle` has no
production caller. Each carries an explicit "invert this when implemented" note
in the module docstring. Section 4 explains why the last two are the ones worth
having.

---

## 3. Claim vs reality

| | |
|---|---|
| **Claim** | `docs/v1.0.0/06-debt-and-quality.md:254` — *"## 6. `withdrawal` audit — the one asset with no plan"*, and `:136` of the index: this section is *"untouched — the `withdrawal` audit"*. |
| **Reality** | No `withdrawal` asset exists. The section's own body (`:256-274`) never uses the word. It is about **the evidence bundle**: `":256` — *"mayhem's genuine differentiator is the evidence bundle: hash-chained, signed, replayable, exportable. Nothing in the market does this. But **nothing in 1.0.0 as planned extends it.**"* |

The section body lists four candidates (pack signer, steady-state verdict,
impact-gate cross-check, v1.0 attestation) and the sequencing table carries two
of them as unstarted (`:289` "Steady-state verdict into the evidence bundle |
not started | M", `:290` "v1.0 catalogue-digest attestation | not started | S";
echoed as a stretch item at `07-release-gates.md:78`). The bundle is also called
mayhem's "genuine differentiator" and "the natural payoff of plans 1 and 2".

**So the section is titled after an asset that does not exist, and the work it
actually describes is the one part of plan 06 that was never planned.** The
index row at `docs/v1.0.0/README.md:136` compounds it by listing §6 among *plans*
(`02`, `03`, `05`, `04`, `07`) as though it were a plan for a feature. It is
not; it is a four-bullet wishlist under a heading that names something else.

---

## 4. The audit the body asks for — and a real defect

Since the section's actual subject is the evidence bundle, I audited it rather
than writing an audit of nothing. The bundle is genuinely the strongest asset in
the repository, and it has a live, user-visible defect that no other lane found.

### 4.1 What works

- `build_bundle` (`src/mayhem/domain/evidence_bundle.py:132-169`) hash-chains
  artifacts deterministically.
- `verify_bundle` (`:240`) re-derives every digest and the root digest offline,
  and reports an unsigned bundle as unsigned.
- `write_bundle` / `load_bundle` (`src/mayhem/infra/evidence_bundle_io.py:27,39`)
  persist and read a bundle directory.
- The domain module has zero filesystem imports; IO is correctly in `infra`.

The rules are good. The plumbing is missing.

### 4.2 Claim: mayhem builds bundles

`src/mayhem/cli/command_registry.py:33`

```python
"bundle": "Build and verify portable evidence bundles.",
```

`src/mayhem/cli/verify_bundle.py:13`

```python
bundle_cmd = make_group("bundle", "Build and verify portable evidence bundles.")
```

This string is not decoration. It is the short help that the CLI prints in
`mayhem --help`, and it is the group's own help. Proved live:

```
$ .venv/bin/mayhem --help
Commands:
  bundle      Build and verify portable evidence bundles.
```

### 4.3 Reality: mayhem cannot build a bundle

```
$ .venv/bin/mayhem bundle --help
Usage: mayhem bundle [OPTIONS] COMMAND [ARGS]...
  Build and verify portable evidence bundles.
Commands:
  show    Print a bundle's manifest without verifying it.
  verify  Verify a bundle's schema, hashes, chain order, signature, and...
```

Two subcommands: `show`, `verify`. There is no `build`. Two independent
confirmations that none is hiding:

1. `write_bundle` — the only function in the tree that writes a
   `manifest.json` (`evidence_bundle_io.py:33`) — has **no production caller**.
   `grep -rn write_bundle src/` returns the definition and two docstring
   references. Every call site is in `tests/`.
2. `build_bundle` is likewise called only from `tests/unit/test_evidence_bundle.py`,
   `test_expansion_checkpoint.py`, `test_steady_state_evaluator.py`,
   `test_v090_edge_cases.py`, `tests/integration/test_bundle_verifier.py`.

The registry agrees: `CommandSpec("bundle", "inspect", ...)`
(`command_registry.py:58`) classifies the group as **inspect** — read-only,
non-mutating. A group that could build would not be filed under `inspect`.

**Net effect: a user of mayhem 1.0 cannot produce an evidence bundle. They can
only verify one that something else produced.** The feature described at
`README.md:440` as *"Hash-chained, offline-verifiable bundles of a run's
evidence"* is half a feature, and the half that ships is the half that reads.

### 4.4 Second defect: the documented two-command recipe does not work

`README.md:476-477`, in the quick-verification block:

```bash
mayhem inspect replay export RUN_ID --out bundle/
mayhem bundle verify bundle/
```

Run against the checkout's own database:

```
$ .venv/bin/mayhem inspect replay export r-ctx --out /tmp/probe-bundle
wrote /tmp/probe-bundle (digest 8c5859a631c3)
$ ls -la /tmp/probe-bundle
-rw-r--r--  1215  /tmp/probe-bundle          # a FILE, not a directory
$ .venv/bin/mayhem bundle verify /tmp/probe-bundle
unreadable bundle: no manifest.json in /tmp/probe-bundle
exit=1
```

`inspect replay export` writes `capsule.model_dump(mode="json")` — one replay
capsule (`src/mayhem/cli/inspect.py:225-228`). A bundle is a *directory*
containing `manifest.json` plus up to four artifacts
(`evidence_bundle.py:30-37`). The two commands produce different shapes, and
the documented sequence terminates in an error. This is the same defect class
as the 18 documentation overclaims the honesty lane already found, in the one
place nobody looked because "bundles" is the feature the plan calls the
differentiator.

### 4.5 The gap, in one buyer-readable sentence

**mayhem tells you it builds signed, hash-chained evidence bundles — the feature
it sells as its differentiator — and ships no way to make one; the recipe in its
own README produces a file the verifier then rejects.**

### 4.6 Honest verdict

| Subject | Verdict |
|---|---|
| `withdrawal` as a named asset | **Absent.** Not working, not partial, not declared — a heading with no referent. |
| The evidence bundle (what §6's body is about) | **Partial, and advertised as whole.** Rules and verification: working. Producer: absent. |

---

## 5. Provenance from the tree, and the limits of it

What the tree does establish:

- **The bundle predates 1.0.0 and calls itself a v0.9.0 artifact.** The module
  docstring is explicit: `src/mayhem/domain/evidence_bundle.py:1` — *"(v0.9.0
  expansion task 20)"*, repeated at `infra/evidence_bundle_io.py:1`. So the
  "expansion task 20" scoped both rules **and** IO, and the IO half stopped at
  `write_bundle` with no caller.
- **The CLI group landed with a "Build" help string and no build command.**
  The string is in both the registry (`:33`) and the group definition
  (`verify_bundle.py:13`) — two authors of the same sentence, or one copied.
  The subcommand set is pinned by `tests/unit/test_cli_active_surface.py:8-27`
  and by `tests/unit/test_v090_docs_contract.py:116-124`, which requires only
  that the *string* `mayhem bundle` appear in the README. Nothing ever asserted
  that a documented subcommand exists. That is why the gap survived: the tests
  pin the group's *name*, never its *verbs*.
- **The README kept the honest half.** `README.md:386` ("Verify a portable
  evidence bundle offline") and `:440` (pointing at `mayhem bundle verify PATH`)
  describe only what exists. The overclaim lives in `--help`, not in the
  README table — which is why the honesty lane's README sweep did not catch it.
- **No 1.0 attempt to fix it.** `docs/v1.0.0/07-release-gates.md:78` still
  lists "v1.0 catalogue-digest attestation in the evidence bundle" as an
  unstarted stretch item. There is no version, no catalogue digest, and no
  steady-state verdict anywhere in the bundle path — `BundleManifest`
  (`evidence_bundle.py:60-70`) carries `schema_version`, `artifacts`,
  `root_digest`, `previous_root`, `signature`, `signer`, `redaction_policy`,
  `created_at`, and nothing else.
- **The fault-expansion record corroborates the pattern.** `docs/new-faults/OUTCOME.md`
  documents two waves of "catalog_only" refusals and two inert params, and its
  wave-1 discipline — "the regression guard asserts three distinct argv so it
  cannot go inert again" — is exactly the discipline `bundle` never received.
  13 refusals shipped with tests; one advertised producer shipped without.

What the tree cannot establish, and I will not guess:

- **When** `bundle` was added, and **whether** a `build` command ever existed.
  `CHANGELOG.md` jumps `0.8.0` → `1.0.0` with **no 0.9.0 section at all**; it
  contains no entry for evidence bundles or replay capsules. The only
  `bundle`-adjacent changelog line is `:260` "Clarify the default installation
  bundle", which is about packaging.
- **Whether the missing producer was deliberate** (bundle construction deferred
  to plan 07's attestation work, or intended for a later release) or an
  oversight. `docs/` contains no ADR, no issue reference, and no note saying
  "build is not implemented". The honest reading is oversight, but the tree
  does not prove intent, and this audit does not assert it.
- **Whether `withdrawal` was ever an asset.** The only two occurrences are the
  two documents that reference each other. The most likely explanation — a
  placeholder in a section title that was never filled in, while the body was
  written about a different subject — is consistent with every piece of
  evidence, and is not proven by any of it.

---

## 6. The plan

Two items, in order. Item 1 is a release blocker for 1.0; item 2 is what §6
actually asked for and is now unblocked by item 1. **I am not manufacturing a
`withdrawal` feature.** There is nothing to finish, cut, or document under that
name except the heading itself, and the heading is handled in item 0.

### Item 0 — retire the phantom heading (XS, docs)

Delete the asset name from both places, and say what §6 is actually for.

- `docs/v1.0.0/06-debt-and-quality.md:254` — retitle to *"## 6. Evidence-bundle
  attestation — the one asset with no plan"*.
- `docs/v1.0.0/README.md:136` — replace the row with one that names the work
  (`evidence-bundle attestation`), keeping the "untouched" status, so the index
  no longer implies a feature named `withdrawal` exists.
- Do **not** delete the section. Its body is the only written statement of the
  1.0 attestation idea, and item 2 needs it.

Rationale for renaming rather than deleting: the string is load-bearing in two
documents and inert in the code. Leaving it is how the next lane repeats this
audit. Cost: two lines, one commit, zero risk.

### Item 1 — close the "Build and verify" overclaim (S, code) — **HONESTY BLOCKER**

The bundle has no producer, and the CLI says it has one. A 1.0 whose premise is
not overselling may not ship with an advertised-and-absent capability. Exactly
two advertising lines, both of which say the same words:

- `src/mayhem/cli/command_registry.py:33` — `"bundle": "Build and verify portable evidence bundles."`
- `src/mayhem/cli/verify_bundle.py:13` — `make_group("bundle", "Build and verify portable evidence bundles.")`

Two mutually exclusive resolutions. **Ship the command; do not ship the string.**

1. **Ship `mayhem bundle build RUN_ID --out DIR` (preferred).** Every input
   already exists and is already loadable: `load_evidence(store, run_id)`
   (`infra/evidence.py:184`), `ReplayRepository.load` / `build_capsule`
   (`infra/replay_repository.py:66,9`), `build_capability_report(engine=,
   evidence=)` (`controller/catalog_report.py:375-382`), and the observations
   tuple already inside the evidence envelope
   (`infra/evidence.py:115`). The command is a thin assembly of four existing
   calls into `build_bundle` (`:132`) plus `write_bundle`
   (`infra/evidence_bundle_io.py:27`). Then:
   - change both help strings to *"Verify a portable evidence bundle offline;
     build one with `mayhem bundle build`."* — or just delete "Build";
   - fix the README recipe at `README.md:476-477` to the two real commands;
   - add a CLI test asserting `bundle build --out` produces a directory that
     `bundle verify` accepts — the round trip that has never existed;
   - flip the two inverted assertions in
     `tests/unit/test_withdrawal_asset.py`.
2. **If the command will not ship in 1.0 (fallback, XS).** Delete the word
   "Build" from both strings, add one line to the README status table saying
   bundles are verified-only because no producer is exposed, and flip
   `test_bundle_group_advertises_build_it_cannot_do` to assert the honest
   string. This is honest but leaves the differentiator unverifiable end to end,
   which is a product decision, not an engineering one — put it to the founder
   with the numbers above.

Estimate: option 1 is ~50 lines of CLI plus two test files. It is smaller than
item 2 and it is what makes item 2 possible.

### Item 2 — the attestation §6 actually wanted (M, code) — **after item 1**

Only meaningful once something can produce a bundle; an attestation over an
artifact nobody can make is theatre. Sequencing matches the plan's own
dependency claim (`:289-290` both "Blocks: plan 1").

- **2a — steady-state verdict into the bundle (M).** The evidence envelope
  already carries a `verdict` field (`infra/evidence.py:30,116`) and a
  `steady_state_evaluations` table exists with
  `phase/passed/measured/expectation` columns — currently **0 rows** in this
  checkout, because plan 03 is 0%. So: add the verdict as a first-class bundle
  artifact, and let it read `absent` honestly until plan 03 lands. Do not
  synthesise a verdict from run outcome.
- **2b — catalogue-digest attestation (S).** One signature over data that
  already exists, exactly as the plan says (`:268-271`). `BundleManifest`
  gains two fields: `mayhem_version` and `catalog_digest` (SHA-256 over
  `CATALOG`, computed by the same `_digest` helper at
  `evidence_bundle.py:54`). Bump `BUNDLE_SCHEMA_VERSION` — `:249` already
  refuses an unknown schema version, so old bundles fail loudly instead of
  silently.
- **2c — the pack signer (M), still gated.** Blocked on plan 5's key material,
  which does not exist. Keep it out of 1.0 scope.

The buyer's payoff, unchanged from `:268-271`: a bundle that says *"produced by
mayhem 1.0.0, catalogue digest abc123"* and is checkable six months later
offline. The plan was right; it was just written about an asset that was never
built.

### Sequencing

| # | Item | Size | Blocks | Honesty |
|---|---|---|---|---|
| 0 | Retire the phantom `withdrawal` heading | XS | — | removes a phantom capability from the plan index |
| 1 | Close the "Build and verify" overclaim | S | 2 | **1.0 blocker** — 2 advertising lines |
| 2 | Steady-state verdict + catalogue-digest attestation | M+S | — | unblocks `07:78` |

### What I am deliberately not doing

Not writing a `withdrawal` method, workflow, fault, or capability. The honest
answer to "finish it, cut it, or document it" for a name with no referent is
**cut it, and say so in the plan index** — item 0. Manufacturing a feature to
fill a heading would be the exact failure mode this lane exists to catch.

---

## 7. Guard

`tests/unit/test_withdrawal_asset.py`, 4 tests, ruff-clean, all passing:

1. `test_no_withdrawal_command_is_dispatchable` — walks the live click tree (90
   paths) and asserts no path contains `withdraw`. Invert when a `withdrawal`
   command registers.
2. `test_no_withdrawal_fault_is_catalogued` — asserts 141 definitions and no id
   containing `withdraw`. Invert when one is catalogued.
3. `test_bundle_group_advertises_build_it_cannot_do` — asserts the subcommand
   set is exactly `{show, verify}` **and** pins the two overclaiming help
   strings. This is the defect report: it is designed to fail the moment
   `mayhem bundle build` exists, so the fix cannot land without someone
   updating the pin.
4. `test_build_bundle_has_no_production_caller` — scans `src/mayhem/**.py` and
   asserts no file outside the allowlist mentions `build_bundle`. Invert when
   a producer lands.

No test here asserts a falsehood. Test 3 asserts the *defect*, not the
*intent*; tests 1, 2 and 4 assert absences that were re-verified by probe
immediately before being written.
