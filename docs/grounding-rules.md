# Persona design rules — mayhem 0.6

Source: `docs/feat-1.md` §2 (personas) — solo operator (primary), CI pipeline
(secondary), SRE on a small team (aspirational). Grounded in
`docs/plan-feat-1.md` Phase C. These rules bind every 0.6 feature that adds a
command or workflow.

## Rule 1 — Stable, re-learnable commands

Never add a command that requires re-learning between sessions.

- Flags are stable once a command ships; a command's job does not rotate
  between releases.
- Every new command ships `--help` with at least one runnable example
  (the solo operator does not read docs before a drill).
- No command changes meaning based on cwd state; if a positional arg is
  required it stays required (e.g. `mayhem recover RUN_ID` — never optional).

## Rule 2 — ASCII default + `--json`

Every new command ships an ASCII-only default output mode and a `--json` mode.

- Human output renders correctly in a plain terminal (no color dependence,
  no unicode grid fences that wrap unpredictably).
- `--json` emits one valid JSON document to stdout; CI reads it with no
  parser beyond the stdlib.
- Default mode is quiet on success unless a result is meaningful; never print
  "progress" noise to stdout that would corrupt a piped `--json`.

## Rule 3 — Gates stay non-bypassable

Safety gates are never bypassable by new commands except through the existing
`--allow-critical` / `--skip-gate` toggles.

- No new flag, command, or configuration layer may implicitly disable the
  impact gate, the admission/refusal gates, or the compensation contract.
- New commands must fail closed: when a gate cannot be evaluated, the command
  says so and does not proceed (mirror `k8s.unsupported` refusal).
- The existing toggles are the *only* opt-outs; a 0.6 feature adds no third
  path.

## Rule 4 — Failures name the next command

Failures must name the next command to run.

- A drill failure prints the at-fault steps and the repair command:
  `mayhem history <id>` to replay, `mayhem recover <id>` when a lease is
  orphaned, `mayhem next` (0.6) to pick the next best cell.
- CI exit codes stay typed (`src/mayhem/cli/exit_codes.py`); the human-facing
  message and the machine code must describe the same failure.
- "Unknown failure" is not a valid message: a command either names a next step
  or says which log/state file holds the answer.

## Rule 5 — One obvious thing per command

Explore runs, next suggests, coverage reports — no command does two jobs.

- A command has exactly one responsibility; compound workflows are built by
  chaining single-purpose commands, not by adding modes to one command.
- If two outputs want to live together, one is the primary output and the
  other is reachable via a subcommand or the evidence record — never both in
  the default view.
- The solo-operator test: a user asked "what command do I run now" must get a
  one-command answer.

## Derived check for review

Rules 4 and 5 are borrowed as review checklist items in plan-feat-4
(Phase D review checklist): every 0.6 PR is reviewed against "does the
failure name the next command" and "is there one obvious thing here".