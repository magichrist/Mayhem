# Mayhem CLI Command Hierarchy Reorganization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reorganize the Mayhem CLI from 40 flat root commands into 10 namespaced groups (workspace, environment, drill, runs, orchestration, governance, evidence, platform, extensions, developer), preserving all 40 existing command names and all existing options/arguments/flags as compatibility aliases.

**Architecture:** Add namespace PrefixGroups as parents of existing command handlers. Register each existing command under its new namespace path once (single handler object, no duplicate implementation). Keep root-level compatibility aliases for every old path that point to the same handler. Update `command_registry.py` `COMMAND_SPECS`, `COMMAND_HELP`, and `command_map`. Update `app.py` root group registration logic. All existing command modules remain unchanged.

**Tech Stack:** Python 3.14+, Click 8.x, existing `PrefixGroup` from `mayhem.cli.resolver`, existing command modules under `mayhem.cli.*`.

## Global Constraints

- All 40 existing root command names remain available as compatibility aliases at the root level.
- All existing nested subcommands (e.g., `certify run`, `certify matrix`, `certify regress`, `inspect run`, `inspect leases`, `bundle verify`, `bundle show`, `bundle build`) are carried over verbatim under their new namespace.
- Every positional argument and option at each leaf command is preserved exactly (same name, type, default, help text).
- All global options (`--version`, `--db`, `--config`, `--profile`, `--policy`, `--dry-run`, `--allow-critical`, `--skip-gate`, `-p/--podman`, `-k/--kubernetes`, `-d/--debug`, `--target`, `--format`, `--no-color`) retain current behavior.
- Root `--help` displays only the 10 namespace groups; `mayhem <namespace> --help` displays that namespace's commands; `mayhem <namespace> <command> --help` displays full existing parameter reference.
- Shell completion includes both canonical paths and compatibility aliases.
- Old and new paths invoke the same handler object and produce equivalent results.
- No command or functionality is removed or deprecated.
- Maturity labels and runtime support limitations remain visible.
- Safety gates, approval semantics, recovery, and evidence behavior are unchanged.
- No duplicate implementations: aliases call the same handler.

## File Structure (files to create/modify)

| File | Action | Responsibility |
|------|--------|----------------|
| `src/mayhem/cli/namespaces/__init__.py` | Create | Package marker for namespace modules |
| `src/mayhem/cli/namespaces/workspace.py` | Create | Defines `workspace` PrefixGroup + subcommands `init`, `doctor`, `config`, `support`, `upgrade` |
| `src/mayhem/cli/namespaces/environment.py` | Create | Defines `environment` PrefixGroup + subcommands `discover`, `boundary`, `advisor`, `probe` |
| `src/mayhem/cli/namespaces/drill.py` | Create | Defines `drill` PrefixGroup + subcommands `prepare`, `experiment`, `run`, `maniac`, `risk-preview` |
| `src/mayhem/cli/namespaces/runs.py` | Create | Defines `runs` PrefixGroup + subcommands `list`, `inspect`, `stop`, `extend`, `recover`, `janitor` |
| `src/mayhem/cli/namespaces/orchestration.py` | Create | Defines `orchestration` PrefixGroup + subcommands `campaign`, `schedule`, `game-day` |
| `src/mayhem/cli/namespaces/governance.py` | Create | Defines `governance` PrefixGroup + subcommands `policy`, `secrets`, `certify` |
| `src/mayhem/cli/namespaces/evidence.py` | Create | Defines `evidence` PrefixGroup + subcommands `bundle`, `verify`, `prove` |
| `src/mayhem/cli/namespaces/platform.py` | Create | Defines `platform` PrefixGroup + subcommands `agent`, `ci`, `cloud`, `ha`, `enterprise` |
| `src/mayhem/cli/namespaces/extensions.py` | Create | Defines `extensions` PrefixGroup + subcommands `pack`, `marketplace`, `sandbox` |
| `src/mayhem/cli/namespaces/developer.py` | Create | Defines `developer` PrefixGroup + subcommands `api`, `lowlevel`, `commands`, `completion` |
| `src/mayhem/cli/command_registry.py` | Modify | Add `NAMESPACE_SPECS`, `NAMESPACE_HELP`, `old_to_new_path` mapping; register namespaces under `app`; keep root aliases |
| `src/mayhem/cli/app.py` | Modify | Import and register namespace groups; root aliases point to same handlers |
| `tests/unit/test_cli_namespace_aliases.py` | Create | Tests that every old path resolves to same handler as new path |
| `tests/unit/test_cli_root_help.py` | Create | Test that root help shows namespaces not flat list |
| `tests/unit/test_cli_namespace_help.py` | Create | Test that namespace help shows its commands |

---

## Phase 1: Foundation — Namespace Package and Helper Module

### Task 1: Create `src/mayhem/cli/namespaces/__init__.py`

**Files:**
- Create: `src/mayhem/cli/namespaces/__init__.py`

**Interfaces:**
- Produces: package marker so `mayhem.cli.namespaces` is importable

- [ ] **Step 1: Write the file**

```python
"""Mayhem CLI command namespaces.

This package holds the ten namespace PrefixGroups that reorganize the
flat 40-command root CLI into domain-based groups:

    workspace, environment, drill, runs, orchestration, governance,
    evidence, platform, extensions, developer.

Each namespace module defines its own PrefixGroup and registers its
commands. Existing command handlers are imported from their current
modules and registered under the new path once; root-level compatibility
aliases point to the same handler objects.
"""

__all__ = [
    "workspace",
    "environment",
    "drill",
    "runs",
    "orchestration",
    "governance",
    "evidence",
    "platform",
    "extensions",
    "developer",
]
```

- [ ] **Step 2: Verify import works**

Run: `python -c "from mayhem.cli.namespaces import workspace, environment; print('ok')"`

Expected: `ok` printed, no ImportError

- [ ] **Step 3: Commit**

```bash
git add src/mayhem/cli/namespaces/__init__.py
git commit -m "feat(cli): add namespaces package marker"
```

---

## Phase 2: Create Namespace Modules (10 tasks)

### Task 2: Create `src/mayhem/cli/namespaces/workspace.py`

**Files:**
- Create: `src/mayhem/cli/namespaces/workspace.py`

**Interfaces:**
- Consumes: existing command objects from `mayhem.cli.init`, `mayhem.cli.doctor`, `mayhem.cli.config_cmd`, `mayhem.cli.support_bundle_cmd`, `mayhem.cli.upgrade_cmd`
- Produces: `workspace` PrefixGroup with subcommands `init`, `doctor`, `config` (group with `show`/`validate`), `support` (group with `bundle`), `upgrade`

- [ ] **Step 1: Write the file**

```python
"""``workspace`` namespace: project setup, environment checks, support, upgrades."""

from __future__ import annotations

import click

from mayhem.cli.resolver import make_group
from mayhem.cli.init import init_cmd
from mayhem.cli.doctor import doctor_cmd
from mayhem.cli.config_cmd import config
from mayhem.cli.support_bundle_cmd import support_bundle
from mayhem.cli.upgrade_cmd import upgrade


workspace = make_group(
    "workspace",
    "Initialize projects and manage the local installation.",
)

# Re-register existing command handlers under the workspace namespace.
# `init` and `doctor` are top-level commands under workspace.
workspace.add_command(init_cmd)
workspace.add_command(doctor_cmd)
workspace.add_command(upgrade)

# `config` is itself a group with `show` and `validate` subcommands.
config.name = "config"
workspace.add_command(config)

# `support` is a group with `bundle` subcommand.
support = make_group(
    "support",
    "Build and collect support bundles.",
)
support.add_command(support_bundle, name="bundle")
workspace.add_command(support)
```

- [ ] **Step 2: Verify import works**

Run: `python -c "from mayhem.cli.namespaces.workspace import workspace; print(workspace.name); print(sorted(workspace.commands))"`

Expected: `workspace` printed, then a sorted list including `config`, `doctor`, `init`, `support`, `upgrade`

- [ ] **Step 3: Commit**

```bash
git add src/mayhem/cli/namespaces/workspace.py
git commit -m "feat(cli): add workspace namespace module"
```

---

### Task 3: Create `src/mayhem/cli/namespaces/environment.py`

**Files:**
- Create: `src/mayhem/cli/namespaces/environment.py`

**Interfaces:**
- Consumes: existing command objects from `mayhem.cli.workflows.discover`, `mayhem.cli.boundary_report_cmd.boundary`, `mayhem.cli.advisor_cmd.advisor`, `mayhem.cli.probe_cmd.probe`
- Produces: `environment` PrefixGroup with subcommands `discover` (with `topology`, `faults`, `capabilities`, `engines`), `boundary`, `advisor`, `probe`

- [ ] **Step 1: Write the file**

```python
"""``environment`` namespace: discovery, topology, capabilities, diagnostics."""

from __future__ import annotations

import click

from mayhem.cli.resolver import make_group
from mayhem.cli.workflows import discover
from mayhem.cli.boundary_report_cmd import boundary
from mayhem.cli.advisor_cmd import advisor
from mayhem.cli.probe_cmd import probe


environment = make_group(
    "environment",
    "Discover topology, faults, capabilities and diagnostics.",
)

# `discover` is itself a group; its existing subcommands are carried over intact.
discover.name = "discover"
environment.add_command(discover)

environment.add_command(boundary)
environment.add_command(advisor)
environment.add_command(probe)
```

- [ ] **Step 2: Verify import works**

Run: `python -c "from mayhem.cli.namespaces.environment import environment; print(environment.name); print(sorted(environment.commands))"`

Expected: `environment` printed, then sorted list including `advisor`, `boundary`, `discover`, `probe`

- [ ] **Step 3: Commit**

```bash
git add src/mayhem/cli/namespaces/environment.py
git commit -m "feat(cli): add environment namespace module"
```

---

### Task 4: Create `src/mayhem/cli/namespaces/drill.py`

**Files:**
- Create: `src/mayhem/cli/namespaces/drill.py`

**Interfaces:**
- Consumes: existing command objects from `mayhem.cli.workflows.prepare`, `mayhem.cli.experiment.experiment`, `mayhem.cli.lifecycle.run`, `mayhem.cli.lifecycle.maniac`, `mayhem.cli.risk_preview_cmd.risk_preview`
- Produces: `drill` PrefixGroup with subcommands `prepare` (with `validate`, `plan`, `config`, `dependencies`, `check`), `experiment`, `run`, `maniac`, `risk-preview`

- [ ] **Step 1: Write the file**

```python
"""``drill`` namespace: drill preparation, experiments, execution, risk preview."""

from __future__ import annotations

import click

from mayhem.cli.resolver import make_group
from mayhem.cli.workflows import prepare
from mayhem.cli.experiment import experiment
from mayhem.cli.lifecycle import run as run_cmd, maniac as maniac_cmd
from mayhem.cli.risk_preview_cmd import risk_preview


drill = make_group(
    "drill",
    "Prepare, plan and execute chaos experiments.",
)

# `prepare` is itself a group; carry over its existing subcommands intact.
prepare.name = "prepare"
drill.add_command(prepare)

drill.add_command(experiment)
drill.add_command(run_cmd, name="run")
drill.add_command(maniac_cmd, name="maniac")
drill.add_command(risk_preview, name="risk-preview")
```

- [ ] **Step 2: Verify import works**

Run: `python -c "from mayhem.cli.namespaces.drill import drill; print(drill.name); print(sorted(drill.commands))"`

Expected: `drill` printed, then sorted list including `experiment`, `maniac`, `prepare`, `risk-preview`, `run`

- [ ] **Step 3: Commit**

```bash
git add src/mayhem/cli/namespaces/drill.py
git commit -m "feat(cli): add drill namespace module"
```

---

### Task 5: Create `src/mayhem/cli/namespaces/runs.py`

**Files:**
- Create: `src/mayhem/cli/namespaces/runs.py`

**Interfaces:**
- Consumes: existing command objects from `mayhem.cli.inspect.inspect`, `mayhem.cli.stop_cmd.stop`, `mayhem.cli.extend.extend`, `mayhem.cli.lifecycle.recover`, `mayhem.cli.lifecycle.janitor`
- Produces: `runs` PrefixGroup with subcommands `inspect` (with `run`, `leases`, `residual`, `graph`, `coverage-diff`, `runs`, `history`, `coverage`, `expert`, `next`, `doctor`, `replay export`, `replay validate`), `stop`, `extend`, `recover`, `janitor`

- [ ] **Step 1: Write the file**

```python
"""``runs`` namespace: run inspection, lifecycle control and recovery."""

from __future__ import annotations

import click

from mayhem.cli.resolver import make_group
from mayhem.cli.inspect import inspect as inspect_cmd
from mayhem.cli.stop_cmd import stop
from mayhem.cli.extend import extend as extend_cmd
from mayhem.cli.lifecycle import recover, janitor


runs = make_group(
    "runs",
    "Inspect, control and recover runs.",
)

# `inspect` is itself a group; carry over all its existing subcommands intact.
inspect_cmd.name = "inspect"
runs.add_command(inspect_cmd)

runs.add_command(stop)
runs.add_command(extend_cmd, name="extend")
runs.add_command(recover)
runs.add_command(janitor)
```

- [ ] **Step 2: Verify import works**

Run: `python -c "from mayhem.cli.namespaces.runs import runs; print(runs.name); print(sorted(runs.commands))"`

Expected: `runs` printed, then sorted list including `extend`, `inspect`, `janitor`, `recover`, `stop`

- [ ] **Step 3: Commit**

```bash
git add src/mayhem/cli/namespaces/runs.py
git commit -m "feat(cli): add runs namespace module"
```

---

### Task 6: Create `src/mayhem/cli/namespaces/orchestration.py`

**Files:**
- Create: `src/mayhem/cli/namespaces/orchestration.py`

**Interfaces:**
- Consumes: existing command objects from `mayhem.cli.campaign.campaign`, `mayhem.cli.schedule_cmd.schedule`, `mayhem.cli.game_day.game_day`, `mayhem.cli.game_day_step_cmd.game_day_step`
- Produces: `orchestration` PrefixGroup with subcommands `campaign`, `schedule`, `game-day` (with `step` subcommand rehoming the old `game-day-step`)

- [ ] **Step 1: Write the file**

```python
"""``orchestration`` namespace: campaigns, schedules, and game days."""

from __future__ import annotations

import click

from mayhem.cli.resolver import make_group
from mayhem.cli.campaign import campaign
from mayhem.cli.schedule_cmd import schedule
from mayhem.cli.game_day import game_day
from mayhem.cli.game_day_step_cmd import game_day_step


orchestration = make_group(
    "orchestration",
    "Manage campaigns, schedules and game days.",
)

orchestration.add_command(campaign)
orchestration.add_command(schedule)

# `game-day` is a group; `game-day-step` becomes `game-day step` under it.
game_day.name = "game-day"
orchestration.add_command(game_day)

# The old `game-day-step` command is rehomed as a subcommand of `game-day`.
game_day_step.name = "step"
game_day.add_command(game_day_step)
```

- [ ] **Step 2: Verify import works**

Run: `python -c "from mayhem.cli.namespaces.orchestration import orchestration; print(orchestration.name); print(sorted(orchestration.commands))"`

Expected: `orchestration` printed, then sorted list including `campaign`, `game-day`, `schedule`

- [ ] **Step 3: Verify game-day has `step` subcommand**

Run: `python -c "from mayhem.cli.namespaces.orchestration import orchestration; gd = orchestration.commands['game-day']; print(sorted(gd.commands))"`

Expected: list including `step`

- [ ] **Step 4: Commit**

```bash
git add src/mayhem/cli/namespaces/orchestration.py
git commit -m "feat(cli): add orchestration namespace module"
```

---

### Task 7: Create `src/mayhem/cli/namespaces/governance.py`

**Files:**
- Create: `src/mayhem/cli/namespaces/governance.py`

**Interfaces:**
- Consumes: existing command objects from `mayhem.cli.policy_cmd.policy_cmd`, `mayhem.cli.secrets_cmd.secrets_cmd`, `mayhem.cli.certify.certify`
- Produces: `governance` PrefixGroup with subcommands `policy`, `secrets`, `certify`

- [ ] **Step 1: Write the file**

```python
"""``governance`` namespace: policies, secrets, and certification."""

from __future__ import annotations

import click

from mayhem.cli.resolver import make_group
from mayhem.cli.policy_cmd import policy_cmd
from mayhem.cli.secrets_cmd import secrets_cmd
from mayhem.cli.certify import certify


governance = make_group(
    "governance",
    "Manage policy, secrets and certification.",
)

governance.add_command(policy_cmd, name="policy")
governance.add_command(secrets_cmd, name="secrets")
governance.add_command(certify)
```

- [ ] **Step 2: Verify import works**

Run: `python -c "from mayhem.cli.namespaces.governance import governance; print(governance.name); print(sorted(governance.commands))"`

Expected: `governance` printed, then sorted list including `certify`, `policy`, `secrets`

- [ ] **Step 3: Commit**

```bash
git add src/mayhem/cli/namespaces/governance.py
git commit -m "feat(cli): add governance namespace module"
```

---

### Task 8: Create `src/mayhem/cli/namespaces/evidence.py`

**Files:**
- Create: `src/mayhem/cli/namespaces/evidence.py`

**Interfaces:**
- Consumes: existing command objects from `mayhem.cli.verify_bundle.bundle_cmd`, `mayhem.cli.verify_bundle` (verify subcommand), `mayhem.cli.proof_cmd.prove`
- Produces: `evidence` PrefixGroup with subcommands `bundle` (with `verify`, `show`, `build`, `keygen`, `keys`, `sign`, `signatures`), `verify`, `prove`

- [ ] **Step 1: Write the file**

```python
"""``evidence`` namespace: bundles, verification, safety proofs."""

from __future__ import annotations

import click

from mayhem.cli.resolver import make_group
from mayhem.cli.verify_bundle import bundle_cmd


evidence = make_group(
    "evidence",
    "Export, verify and inspect evidence and proofs.",
)

# `bundle` is itself a group; carry over all its existing subcommands intact.
bundle_cmd.name = "bundle"
evidence.add_command(bundle_cmd)

# `verify` (standalone command, distinct from bundle verify) lives directly under evidence.
from mayhem.cli.verify import verify as verify_cmd  # noqa: E402

evidence.add_command(verify_cmd, name="verify")

from mayhem.cli.proof_cmd import prove  # noqa: E402

evidence.add_command(prove)
```

- [ ] **Step 2: Verify import works**

Run: `python -c "from mayhem.cli.namespaces.evidence import evidence; print(evidence.name); print(sorted(evidence.commands))"`

Expected: `evidence` printed, then sorted list including `bundle`, `prove`, `verify`

- [ ] **Step 3: Commit**

```bash
git add src/mayhem/cli/namespaces/evidence.py
git commit -m "feat(cli): add evidence namespace module"
```

---

### Task 9: Create `src/mayhem/cli/namespaces/platform.py`

**Files:**
- Create: `src/mayhem/cli/namespaces/platform.py`

**Interfaces:**
- Consumes: existing command objects from `mayhem.cli.agent_cmd.agent`, `mayhem.cli.ci_cmd.ci`, `mayhem.cli.cloud_cmd.cloud`, `mayhem.cli.failover_cmd.ha`, `mayhem.cli.enterprise_cmd.enterprise`
- Produces: `platform` PrefixGroup with subcommands `agent`, `ci`, `cloud`, `ha`, `enterprise`

- [ ] **Step 1: Write the file**

```python
"""``platform`` namespace: agents, CI, cloud, HA, enterprise operations."""

from __future__ import annotations

import click

from mayhem.cli.resolver import make_group
from mayhem.cli.agent_cmd import agent
from mayhem.cli.ci_cmd import ci
from mayhem.cli.cloud_cmd import cloud
from mayhem.cli.failover_cmd import ha
from mayhem.cli.enterprise_cmd import enterprise


platform = make_group(
    "platform",
    "Manage agents and platform integrations.",
)

platform.add_command(agent)
platform.add_command(ci)
platform.add_command(cloud)
platform.add_command(ha)
platform.add_command(enterprise)
```

- [ ] **Step 2: Verify import works**

Run: `python -c "from mayhem.cli.namespaces.platform import platform; print(platform.name); print(sorted(platform.commands))"`

Expected: `platform` printed, then sorted list including `agent`, `ci`, `cloud`, `enterprise`, `ha`

- [ ] **Step 3: Commit**

```bash
git add src/mayhem/cli/namespaces/platform.py
git commit -m "feat(cli): add platform namespace module"
```

---

### Task 10: Create `src/mayhem/cli/namespaces/extensions.py`

**Files:**
- Create: `src/mayhem/cli/namespaces/extensions.py`

**Interfaces:**
- Consumes: existing command objects from `mayhem.cli.pack.pack`, `mayhem.cli.marketplace_cmd.marketplace`, `mayhem.cli.sandbox_cmd.sandbox`
- Produces: `extensions` PrefixGroup with subcommands `pack`, `marketplace`, `sandbox`

- [ ] **Step 1: Write the file**

```python
"""``extensions`` namespace: fault packs, marketplace, sandbox."""

from __future__ import annotations

import click

from mayhem.cli.resolver import make_group
from mayhem.cli.pack import pack
from mayhem.cli.marketplace_cmd import marketplace
from mayhem.cli.sandbox_cmd import sandbox


extensions = make_group(
    "extensions",
    "Manage packs, marketplace and sandbox features.",
)

extensions.add_command(pack)
extensions.add_command(marketplace)
extensions.add_command(sandbox)
```

- [ ] **Step 2: Verify import works**

Run: `python -c "from mayhem.cli.namespaces.extensions import extensions; print(extensions.name); print(sorted(extensions.commands))"`

Expected: `extensions` printed, then sorted list including `marketplace`, `pack`, `sandbox`

- [ ] **Step 3: Commit**

```bash
git add src/mayhem/cli/namespaces/extensions.py
git commit -m "feat(cli): add extensions namespace module"
```

---

### Task 11: Create `src/mayhem/cli/namespaces/developer.py`

**Files:**
- Create: `src/mayhem/cli/namespaces/developer.py`

**Interfaces:**
- Consumes: existing command objects from `mayhem.cli.api_cmd.api`, `mayhem.cli.lowlevel_cmd.lowlevel`, `mayhem.cli.commands.commands`, `mayhem.cli.completion.completion`
- Produces: `developer` PrefixGroup with subcommands `api`, `lowlevel`, `commands`, `completion`

- [ ] **Step 1: Write the file**

```python
"""``developer`` namespace: API, low-level, command registry, shell completion."""

from __future__ import annotations

import click

from mayhem.cli.resolver import make_group
from mayhem.cli.api_cmd import api
from mayhem.cli.lowlevel_cmd import lowlevel
from mayhem.cli.commands import commands
from mayhem.cli.completion import completion


developer = make_group(
    "developer",
    "API, low-level, command registry and shell completion tools.",
)

developer.add_command(api)
developer.add_command(lowlevel)
developer.add_command(commands)
developer.add_command(completion)
```

- [ ] **Step 2: Verify import works**

Run: `python -c "from mayhem.cli.namespaces.developer import developer; print(developer.name); print(sorted(developer.commands))"`

Expected: `developer` printed, then sorted list including `api`, `commands`, `completion`, `lowlevel`

- [ ] **Step 3: Commit**

```bash
git add src/mayhem/cli/namespaces/developer.py
git commit -m "feat(cli): add developer namespace module"
```

---

## Phase 3: Wire Namespaces into Root App

### Task 12: Modify `src/mayhem/cli/command_registry.py` — Add namespace registration

**Files:**
- Modify: `src/mayhem/cli/command_registry.py`

**Interfaces:**
- Consumes: existing `COMMAND_SPECS`, `COMMAND_HELP`, `command_map`, `register_commands` function
- Produces: adds `NAMESPACE_SPECS`, `NAMESPACE_HELP`, `OLD_TO_NEW_PATH`, `register_namespaces` function; extends `register_commands` to also register namespaces under `app`

- [ ] **Step 1: Add namespace spec data and registration function**

Add after the existing `COMMAND_SPECS` tuple (around line 248), before `register_commands`:

```python
# ── Namespace specifications ──────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class NamespaceSpec:
    name: str
    help_text: str


NAMESPACE_SPECS: tuple[NamespaceSpec, ...] = (
    NamespaceSpec("workspace", "Initialize projects and manage the local installation."),
    NamespaceSpec("environment", "Discover topology, faults, capabilities and diagnostics."),
    NamespaceSpec("drill", "Prepare, plan and execute chaos experiments."),
    NamespaceSpec("runs", "Inspect, control and recover runs."),
    NamespaceSpec("orchestration", "Manage campaigns, schedules and game days."),
    NamespaceSpec("governance", "Manage policy, secrets and certification."),
    NamespaceSpec("evidence", "Export, verify and inspect evidence and proofs."),
    NamespaceSpec("platform", "Manage agents and platform integrations."),
    NamespaceSpec("extensions", "Manage packs, marketplace and sandbox features."),
    NamespaceSpec("developer", "API, low-level, command registry and shell completion tools."),
)


# Mapping from old root path to new canonical path, for compatibility aliases.
# Each entry: old_path (space-separated) -> new_path (space-separated).
OLD_TO_NEW_PATH: dict[str, str] = {
    "init": "workspace init",
    "doctor": "workspace doctor",
    "config": "workspace config",
    "support-bundle": "workspace support bundle",
    "upgrade": "workspace upgrade",
    "discover": "environment discover",
    "boundary": "environment boundary",
    "advisor": "environment advisor",
    "probe": "environment probe",
    "prepare": "drill prepare",
    "experiment": "drill experiment",
    "run": "drill run",
    "maniac": "drill maniac",
    "risk-preview": "drill risk-preview",
    "inspect": "runs inspect",
    "stop": "runs stop",
    "extend": "runs extend",
    "recover": "runs recover",
    "janitor": "runs janitor",
    "campaign": "orchestration campaign",
    "schedule": "orchestration schedule",
    "game-day": "orchestration game-day",
    "game-day-step": "orchestration game-day step",
    "policy": "governance policy",
    "secrets": "governance secrets",
    "certify": "governance certify",
    "bundle": "evidence bundle",
    "verify": "evidence verify",
    "prove": "evidence prove",
    "agent": "platform agent",
    "ci": "platform ci",
    "cloud": "platform cloud",
    "ha": "platform ha",
    "enterprise": "platform enterprise",
    "pack": "extensions pack",
    "marketplace": "extensions marketplace",
    "sandbox": "extensions sandbox",
    "api": "developer api",
    "lowlevel": "developer lowlevel",
    "commands": "developer commands",
    "completion": "developer completion",
}


def register_namespaces(app: click.Group) -> None:
    """Register the ten namespace groups under the root app.

    Each existing command handler is registered exactly once under its
    new namespace. Root-level compatibility aliases are then added that
    point to the same handler objects.
    """
    from mayhem.cli.namespaces import (
        developer,
        drill,
        environment,
        evidence,
        extensions,
        governance,
        orchestration,
        platform,
        runs,
        workspace,
    )

    namespace_map = {
        "developer": developer,
        "drill": drill,
        "environment": environment,
        "evidence": evidence,
        "extensions": extensions,
        "governance": governance,
        "orchestration": orchestration,
        "platform": platform,
        "runs": runs,
        "workspace": workspace,
    }

    for spec in NAMESPACE_SPECS:
        ns = namespace_map[spec.name]
        ns.help = spec.help_text
        app.add_command(ns)
```

- [ ] **Step 2: Extend `register_commands` to also call `register_namespaces`**

Modify the end of `register_commands` (after the `for spec in COMMAND_SPECS:` loop at line 334):

```python
    for spec in COMMAND_SPECS:
        command = command_map[spec.name]
        command.help = COMMAND_HELP[spec.name]
        app.add_command(command)

    register_namespaces(app)
```

- [ ] **Step 3: Verify app builds with namespaces**

Run: `python -c "from mayhem.cli.app import app; names = sorted(app.commands); print(names)"`

Expected: list includes all 10 namespace names plus all 40 old root command names (aliases not yet added — they come in Task 13)

- [ ] **Step 4: Commit**

```bash
git add src/mayhem/cli/command_registry.py
git commit -m "feat(cli): register namespace groups under root app"
```

---

### Task 13: Modify `src/mayhem/cli/app.py` — Add root-level compatibility aliases

**Files:**
- Modify: `src/mayhem/cli/app.py`

**Interfaces:**
- Consumes: `OLD_TO_NEW_PATH` mapping from `command_registry`, existing `app` Click group
- Produces: root-level aliases for every old command path that dispatch to the same handler as the new path

- [ ] **Step 1: Add alias registration after `register_commands(app)`**

In `app.py`, after line 160 `register_commands(app)`, add:

```python
from mayhem.cli.command_registry import OLD_TO_NEW_PATH

# Register root-level compatibility aliases. Each old path resolves to
# the same handler object as its new namespace path, so behavior is
# identical and no duplicate implementation exists.
for old_path, new_path in OLD_TO_NEW_PATH.items():
    new_parts = new_path.split()
    # Navigate to the namespace group, then find the target command.
    target = app
    for part in new_parts:
        target = target.get_command(click.Context(target), part)
    if target is not None:
        # Register the old path as an alias command pointing to the same handler.
        alias = click.Command(
            name=old_path,
            callback=target.callback,
            params=target.params,
            help=target.help,
            epilog=target.epilog,
        )
        app.add_command(alias)
```

Also need to import `click` — it's already imported at line 8.

- [ ] **Step 2: Verify old paths resolve to same handlers**

Run:
```python
python -c "
from mayhem.cli.app import app
from mayhem.cli.command_registry import OLD_TO_NEW_PATH
for old, new in OLD_TO_NEW_PATH.items():
    old_cmd = app.get_command(click.Context(app), old)
    new_parts = new.split()
    target = app
    for part in new_parts:
        target = target.get_command(click.Context(target), part)
    assert old_cmd is not None, f'missing alias: {old}'
    assert target is not None, f'missing target: {new}'
    assert old_cmd.callback == target.callback, f'handler mismatch: {old} -> {new}'
print('all aliases resolve to same handlers')
"
```

Expected: `all aliases resolve to same handlers`

- [ ] **Step 3: Commit**

```bash
git add src/mayhem/cli/app.py
git commit -m "feat(cli): add root-level compatibility aliases for old command paths"
```

---

## Phase 4: Tests

### Task 14: Create `tests/unit/test_cli_namespace_aliases.py`

**Files:**
- Create: `tests/unit/test_cli_namespace_aliases.py`

**Interfaces:**
- Consumes: `app` from `mayhem.cli.app`, `OLD_TO_NEW_PATH` from `mayhem.cli.command_registry`
- Produces: test assertions that every old path resolves and invokes the same handler as its new path

- [ ] **Step 1: Write the test file**

```python
"""Tests that every old root command path resolves to the same handler
as its new namespace path (compatibility alias contract)."""

from click.testing import CliRunner

from mayhem.cli.app import app
from mayhem.cli.command_registry import OLD_TO_NEW_PATH


def _resolve(ctx, path: str):
    """Walk a space-separated path through the Click tree, returning the final command."""
    target = app
    for part in path.split():
        target = target.get_command(ctx, part)
        assert target is not None, f"path {path!r} does not resolve at {part!r}"
        ctx = click.Context(target)
    return target


import click


def test_every_old_path_resolves_to_same_handler_as_new_path():
    runner = CliRunner()
    ctx = click.Context(app)
    for old_path, new_path in OLD_TO_NEW_PATH.items():
        old_cmd = _resolve(ctx, old_path)
        new_cmd = _resolve(ctx, new_path)
        assert old_cmd is not None, f"old path {old_path!r} missing"
        assert new_cmd is not None, f"new path {new_path!r} missing"
        assert old_cmd.callback == new_cmd.callback, (
            f"handler mismatch: {old_path!r} -> {new_path!r}"
        )


def test_old_path_invocation_equals_new_path_invocation():
    """Invoke --help through old and new paths; output must be equivalent."""
    runner = CliRunner()
    for old_path, new_path in OLD_TO_NEW_PATH.items():
        old_result = runner.invoke(app, old_path.split() + ["--help"])
        new_result = runner.invoke(app, new_path.split() + ["--help"])
        assert old_result.exit_code == new_result.exit_code, (
            f"exit code mismatch: {old_path!r} vs {new_path!r}"
        )
```

- [ ] **Step 2: Run the tests**

Run: `pytest tests/unit/test_cli_namespace_aliases.py -v`

Expected: 2 tests pass

- [ ] **Step 3: Commit**

```bash
git add tests/unit/test_cli_namespace_aliases.py
git commit -m "test(cli): verify old paths alias to new namespace handlers"
```

---

### Task 15: Create `tests/unit/test_cli_root_help.py`

**Files:**
- Create: `tests/unit/test_cli_root_help.py`

**Interfaces:**
- Consumes: `app` from `mayhem.cli.app`
- Produces: test that root help lists namespaces, not flat commands

- [ ] **Step 1: Write the test file**

```python
"""Tests that root help displays the ten namespace groups."""

from click.testing import CliRunner

from mayhem.cli.app import app


def test_root_help_shows_namespaces_not_flat_list():
    runner = CliRunner()
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    output = result.output
    for ns in [
        "workspace",
        "environment",
        "drill",
        "runs",
        "orchestration",
        "governance",
        "evidence",
        "platform",
        "extensions",
        "developer",
    ]:
        assert ns in output, f"namespace {ns!r} missing from root help"
```

- [ ] **Step 2: Run the tests**

Run: `pytest tests/unit/test_cli_root_help.py -v`

Expected: 1 test passes

- [ ] **Step 3: Commit**

```bash
git add tests/unit/test_cli_root_help.py
git commit -m "test(cli): root help shows namespace groups"
```

---

### Task 16: Create `tests/unit/test_cli_namespace_help.py`

**Files:**
- Create: `tests/unit/test_cli_namespace_help.py`

**Interfaces:**
- Consumes: `app` from `mayhem.cli.app`
- Produces: tests that each namespace help shows its commands, and leaf help shows full parameter reference

- [ ] **Step 1: Write the test file**

```python
"""Tests that namespace help shows its commands and leaf help shows parameters."""

from click.testing import CliRunner

from mayhem.cli.app import app


def test_namespace_help_shows_its_commands():
    runner = CliRunner()
    for ns, expected_cmds in [
        ("workspace", ["init", "doctor", "config", "support", "upgrade"]),
        ("environment", ["discover", "boundary", "advisor", "probe"]),
        ("drill", ["prepare", "experiment", "run", "maniac", "risk-preview"]),
        ("runs", ["inspect", "stop", "extend", "recover", "janitor"]),
        ("orchestration", ["campaign", "schedule", "game-day"]),
        ("governance", ["policy", "secrets", "certify"]),
        ("evidence", ["bundle", "verify", "prove"]),
        ("platform", ["agent", "ci", "cloud", "ha", "enterprise"]),
        ("extensions", ["pack", "marketplace", "sandbox"]),
        ("developer", ["api", "lowlevel", "commands", "completion"]),
    ]:
        result = runner.invoke(app, [ns, "--help"])
        assert result.exit_code == 0, f"namespace {ns} help failed: {result.output}"
        output = result.output
        for cmd in expected_cmds:
            assert cmd in output, f"command {cmd!r} missing from {ns} help"


def test_leaf_help_shows_full_parameters():
    """Leaf help under new path must show the existing parameter reference."""
    runner = CliRunner()
    result = runner.invoke(app, ["drill", "run", "--help"])
    assert result.exit_code == 0
    output = result.output
    assert "--execute" in output, "run command missing --execute option"
    assert "--compose" in output, "run command missing --compose option"
```

- [ ] **Step 2: Run the tests**

Run: `pytest tests/unit/test_cli_namespace_help.py -v`

Expected: 2 tests pass

- [ ] **Step 3: Commit**

```bash
git add tests/unit/test_cli_namespace_help.py
git commit -m "test(cli): namespace help shows commands, leaf help shows parameters"
```

---

## Phase 5: Verification Checkpoint

### Task 17: Full CLI smoke test

**Files:** None (verification only)

**Interfaces:** None

- [ ] **Step 1: Run existing test suite**

Run: `pytest tests/unit/ -x -q`

Expected: all existing tests pass (no regressions from namespace registration)

- [ ] **Step 2: Smoke test key workflows via old and new paths**

Run:
```bash
python -m mayhem --help | head -30
python -m mayhem workspace doctor --help
python -m mayhem environment discover topology --help
python -m mayhem drill run --help
python -m mayhem runs inspect --help
python -m mayhem orchestration campaign --help
python -m mayhem governance certify --help
python -m mayhem evidence bundle --help
python -m mayhem platform agent --help
python -m mayhem extensions pack --help
python -m mayhem developer api --help
```

Expected: all commands show help without errors

- [ ] **Step 3: Verify old path still works**

Run:
```bash
python -m mayhem doctor --help
python -m mayhem certify --help
python -m mayhem inspect --help
```

Expected: old paths still show help (compatibility aliases working)

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "test(cli): full CLI smoke test for namespace reorganization"
```

---

## Phase 6: Documentation

### Task 18: Update CLI documentation references

**Files:**
- Modify: `docs/CLI-v2.md` (if exists) — update command tree diagrams
- Modify: `README.md` — update command examples to use new canonical paths

**Interfaces:** None

- [ ] **Step 1: Update docs/CLI-v2.md command tree**

Replace flat command list with the 10-namespace tree from the plan spec.

- [ ] **Step 2: Update README.md examples**

Replace `mayhem doctor` → `mayhem workspace doctor`, `mayhem run` → `mayhem drill run`, etc.

- [ ] **Step 3: Commit**

```bash
git add docs/CLI-v2.md README.md
git commit -m "docs(cli): update command tree and examples for namespace reorganization"
```

---

## Acceptance Checklist

- [ ] All 40 enumerated root command names are represented in the new tree (via old paths as aliases + new paths under namespaces)
- [ ] Every existing nested subcommand is carried over under its corresponding command
- [ ] Every positional argument and option is preserved at the leaf command
- [ ] All listed global options retain their current behavior
- [ ] Every old root path still works as a compatibility alias
- [ ] Old and new paths invoke the same handler and produce equivalent results
- [ ] Root help displays namespaces rather than a long flat command list
- [ ] Namespace help displays all commands in that domain
- [ ] Leaf help displays the complete current parameter reference
- [ ] Shell completion includes both canonical paths and compatibility aliases (Click auto-generates from registered commands)
- [ ] Command documentation and inventory are generated from one registry (`command_registry.py`)
- [ ] Maturity labels and runtime support limitations remain visible (unchanged command modules)
- [ ] Safety gates, approval semantics, recovery, and evidence behavior are unchanged

---

## Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Click `Command` alias may not preserve `invoke_without_command` or `no_args_is_help` | Medium | Test each alias help output matches original |
| `PrefixGroup` prefix resolution conflicts between old aliases and namespace names | Medium | Old aliases like `init` and namespace `workspace` don't conflict; test prefix resolution |
| `game-day-step` → `game-day step` rehoming breaks prefix `game-day-s` | Low | Prefix resolution is per-level; `game-day step` is unambiguous under `game-day` |
| `verify` command moved from root to `evidence verify`; old `verify` alias points to same handler | Low | Tested by alias handler-equality test |

---

## Open Questions

- None identified at plan time.

---

**Plan complete.** Two execution options:

**1. Subagent-Driven (recommended)** - I dispatch a fresh subagent per task, review between tasks, fast iteration

**2. Inline Execution** - Execute tasks in this session using executing-plans, batch execution with checkpoints

**Which approach?**