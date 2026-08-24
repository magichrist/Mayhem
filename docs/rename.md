# Task: Rename the Project to `mayhem` and Redesign the CLI

The project's official name is now:

# mayhem

Use **mayhem** consistently throughout the entire project.

This is not merely a cosmetic rename. Treat it as a project-wide identity change and simultaneously establish a robust CLI architecture suitable for the planned chaos-engineering framework.

---

## 1. Rename Everything to mayhem

Replace the current project/framework name with:

```text
mayhem
```

Audit the entire repository for the old project name and update it where appropriate.

Check:

* `pyproject.toml`
* package/module names where appropriate
* source code
* CLI entry points
* imports
* configuration
* YAML examples
* documentation
* README
* architecture diagrams
* comments
* logging
* error messages
* database metadata where applicable
* environment variables
* Docker/Compose configuration
* test names
* fixtures
* CI/CD
* scripts
* documentation URLs/placeholders
* generated help text
* project metadata

Do not blindly rename identifiers where doing so would break Python conventions or external compatibility.

If the old name is part of a technical identifier that should remain temporarily for compatibility, document that decision.

The user-facing product name must be:

```text
mayhem
```

---

# 2. CLI Must Be a First-Class Architecture

The CLI should not be treated as a thin collection of commands.

Design it as a proper command tree that can grow substantially as mayhem evolves.

The CLI must support commands and nested subcommands.

For example:

```bash
mayhem
mayhem init
mayhem validate
mayhem discover
mayhem run
mayhem recover
mayhem status
mayhem history
mayhem agents
mayhem toolkit
mayhem experiment
mayhem config
mayhem target
mayhem maniac
```

The exact final command tree should be determined from the existing project architecture, but it must be designed for significant future expansion.

---

# 3. Command Abbreviation / Prefix Matching

A major requirement is that commands must support **unique-prefix invocation**.

For example, if the canonical command is:

```bash
mayhem recover
```

the following should work:

```bash
mayhem recover
mayhem rec
mayhem re
mayhem r
```

**provided the abbreviation is unambiguous.**

Do NOT hardcode aliases individually like:

```text
r = recover
re = recover
rec = recover
```

Instead implement a general command-resolution mechanism.

Conceptually:

```text
User input
    ↓
Exact command?
    │
    ├── yes → execute
    │
    └── no
         ↓
Unique prefix?
    │
    ├── yes → resolve → execute
    │
    └── no
         ↓
Ambiguous / unknown command
```

---

# 4. Ambiguity Must Be Handled Safely

If multiple commands match the prefix, mayhem must NOT arbitrarily choose one.

For example, if:

```text
mayhem status
mayhem start
```

both begin with `s`, then:

```bash
mayhem s
```

must produce a useful ambiguity error.

Example:

```text
Ambiguous command: "s"

Possible commands:
  status
  start

Use a longer prefix:
  mayhem st
  mayhem sta
```

The resolution algorithm must always prefer:

1. exact match
2. unique prefix
3. otherwise explicit ambiguity error

Never guess between multiple commands.

---

# 5. Prefix Resolution Must Work Recursively

The same behavior must work at every level.

For example:

```bash
mayhem agent list
```

should potentially allow:

```bash
mayhem a l
mayhem ag li
mayhem age lis
```

if those prefixes are uniquely resolvable.

Likewise:

```bash
mayhem experiment run
```

could support:

```bash
mayhem e r
mayhem ex ru
```

The resolver should operate on the complete command tree rather than only the first argument.

---

# 6. Do Not Make Flags Ambiguous

Command-prefix resolution applies to **commands and subcommands**, not arbitrary option names.

For example:

```bash
mayhem recover --force
```

should remain standard CLI syntax.

Do not create dangerous automatic abbreviation behavior for flags unless the selected CLI framework provides a safe and explicit mechanism.

The priority is predictable behavior.

---

# 7. CLI Framework

Inspect the existing implementation and choose an appropriate Python CLI architecture.

Possible technologies include:

* Typer
* Click
* argparse
* another mature Python CLI framework

Choose based on:

* nested commands
* extensibility
* type safety
* help generation
* command resolution
* testing
* maintainability
* future plugin/toolkit integration

Do not choose a library simply because it is popular.

Explain the decision.

If the current implementation already uses a suitable CLI framework, adapt it rather than unnecessarily replacing it.

---

# 8. Recommended Command Architecture

Design the command system around explicit command metadata rather than scattering command parsing throughout the application.

Conceptually:

```text
CLI
├── Command Registry
├── Command Resolver
├── Command Context
├── Argument Parser
├── Help Renderer
├── Error Renderer
└── Command Handlers
```

The command handler should not contain the core business logic.

Prefer:

```text
CLI command
    ↓
Application service
    ↓
Domain
    ↓
Infrastructure
```

rather than:

```text
CLI command
    ↓
direct subprocess/database/network operations
```

This keeps the CLI replaceable by a future REST API or Web UI.

---

# 9. Proposed Command Groups

Review the existing architecture and create a coherent initial command hierarchy.

At minimum consider:

```text
mayhem
├── init
├── validate
├── discover
├── run
├── recover
├── status
├── history
│
├── experiment
│   ├── list
│   ├── show
│   ├── validate
│   ├── run
│   └── delete
│
├── agent
│   ├── list
│   ├── status
│   ├── start
│   ├── stop
│   └── inspect
│
├── toolkit
│   ├── list
│   ├── inspect
│   ├── check
│   └── doctor
│
├── target
│   ├── list
│   ├── inspect
│   └── discover
│
├── config
│   ├── show
│   ├── validate
│   └── explain
│
└── maniac
    ├── run
    ├── status
    ├── history
    └── stop
```

This is a starting point, NOT a requirement to implement every command immediately.

Separate:

### MVP commands

from:

### Future commands

Do not implement placeholder commands merely to make the tree look complete.

---

# 10. Short Commands

Where appropriate, support intentional short aliases for commonly used commands.

For example:

```bash
mayhem r
```

may resolve to:

```bash
mayhem recover
```

but only through the general prefix resolver.

Avoid creating a huge list of manually maintained aliases.

The system should naturally allow:

```bash
mayhem re
mayhem rec
mayhem reco
mayhem recov
mayhem recover
```

when the prefix is unique.

---

# 11. Help Must Understand Prefixes

Help should explain this capability.

For example:

```bash
mayhem --help
```

should include something similar to:

```text
Commands may be abbreviated using unique prefixes.

Examples:
  mayhem recover
  mayhem rec
  mayhem re

If a prefix matches multiple commands, mayhem will ask you
to provide a longer prefix.
```

Also make ambiguity errors educational.

---

# 12. Safety-Critical Commands

mayhem is a chaos-engineering framework.

Some commands can intentionally damage systems.

Commands such as:

```bash
mayhem run
mayhem maniac
mayhem recover
mayhem agent ...
```

must be designed with the safety architecture already established by the project.

Do not weaken existing safety controls merely to make the CLI convenient.

For dangerous commands, preserve:

* target validation
* environment validation
* blast-radius limits
* duration limits
* authorization
* dry-run
* confirmation where appropriate
* emergency recovery
* audit logging

Prefix resolution must NEVER bypass safety checks.

For example:

```bash
mayhem m
```

resolving to `maniac` must still execute exactly the same safety pipeline as:

```bash
mayhem maniac
```

---

# 13. Error Handling

Design consistent CLI errors.

Examples:

### Unknown

```text
Unknown command: "recovr"

Did you mean:
  recover
```

### Ambiguous

```text
Ambiguous command: "r"

Possible commands:
  recover
  run

Use a longer prefix.
```

### Dangerous operation

```text
Refusing to execute experiment.

Reason:
Target environment has not been explicitly authorized.

Run:
  mayhem validate
```

Do not leak stack traces during normal CLI operation.

Provide a debug mode for full diagnostics.

---

# 14. Exit Codes

Define consistent exit codes.

At minimum distinguish:

```text
0   success
1   general failure
2   CLI usage error
3   configuration error
4   target validation failure
5   safety refusal
6   experiment failure
7   recovery failure
8   agent failure
9   toolkit failure
10  ambiguous command
```

Do not blindly use these exact numbers if the existing project has a better convention, but establish a documented and stable scheme.

---

# 15. Testing

Add comprehensive CLI tests.

Test:

### Exact commands

```bash
mayhem recover
```

### Unique prefixes

```bash
mayhem rec
mayhem re
```

### Nested prefixes

```bash
mayhem e r
mayhem ex ru
```

### Ambiguous prefixes

```bash
mayhem r
```

when multiple `r*` commands exist.

### Unknown commands

```bash
mayhem xyz
```

### Help

```bash
mayhem --help
mayhem recover --help
```

### Safety

Verify that:

```bash
mayhem m
```

cannot bypass any safety mechanism that:

```bash
mayhem maniac
```

would enforce.

### Exit codes

Verify every documented failure category.

---

# 16. Completion and Future UX

Leave room for:

* shell completion
* Bash
* Zsh
* Fish
* PowerShell
* interactive experiment selection
* JSON output
* machine-readable output
* REST API
* Web UI

Do not overbuild these now.

The command architecture should make them possible later.

---

# 17. Rename Verification

After implementing the rename, perform a repository-wide audit.

Search for:

* old project name
* old CLI command
* old package name
* old configuration keys
* old documentation
* old environment variables
* stale examples
* stale test references

Also verify:

```bash
mayhem --help
mayhem validate
mayhem discover
```

work correctly.

Verify that the package can be installed and that the CLI entry point is correctly registered.

---

# 18. Important Constraint

Do NOT redesign the entire chaos-engineering architecture while doing this task.

The previous architecture remains authoritative:

```text
Controller
    ↓
Configuration
    ↓
Experiment Planner
    ↓
~12 Agents
    ↓
Toolkit Arsenal
    ↓
Native / external tools
    ↓
Targets
    ↓
Observation
    ↓
Recovery
    ↓
SQLite history
```

The CLI is the interface into that architecture.

Keep the domain/application layer independent from the CLI so future interfaces can reuse it.

---

# 19. Deliverables

Before modifying code:

1. Inspect the existing repository.
2. Identify the current project name and CLI architecture.
3. Identify the current command tree.
4. Identify the current configuration and application layers.
5. Identify compatibility concerns.
6. Produce a concise implementation plan.

Then implement:

* project rename to **mayhem**
* CLI command registry
* hierarchical command tree
* unique-prefix resolver
* ambiguity handling
* consistent errors
* exit codes
* help documentation
* tests
* updated project metadata
* updated documentation

Finally provide:

```text
1. Files changed
2. Architecture decisions
3. New CLI command tree
4. Prefix-resolution behavior
5. Tests added
6. Compatibility concerns
7. Remaining work
```

Do not stop at renaming strings. The resulting CLI should establish a strong foundation for mayhem's future command surface.
