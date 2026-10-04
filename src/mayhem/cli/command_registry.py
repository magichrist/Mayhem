from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class CommandSpec:
    name: str
    workflow: str
    help_group: str = "general"
    mutating: bool = False


COMMAND_HELP: dict[str, str] = {
    "campaign": "Create, inspect, and run chaos campaigns.",
    "certify": "Certify faults on live runtime cells and query the certification matrix.",
    "commands": "Show the command migration map.",
    "completion": "Generate a shell completion script for this Mayhem build.",
    "discover": "Discover targets, engines, and capabilities.",
    "doctor": "Check configuration, database, engines, and permissions.",
    "experiment": "Inspect and validate authored experiment specs.",
    "extend": "Extend fault and capability coverage safely.",
    "game-day": "Plan and run controlled game-day sessions.",
    "init": "Detect the project and create a safe starting configuration.",
    "inspect": "Inspect runs, coverage, leases, reports, and diagnostics.",
    "pack": "Validate and load third-party fault packs.",
    "janitor": "Preview or execute stale lease cleanup.",
    "maniac": "Run randomized fault injection from a drill.",
    "prepare": "Prepare configuration, dependencies, and plans.",
    "recover": "Plan or execute recovery for a run.",
    "run": "Compile, approve, execute, and record a drill.",
    "stop": "Stop one run, or every live run in an environment, and show what happened.",
    "verify": "Verify a recorded evidence envelope without mutation.",
    "bundle": "Build and verify portable evidence bundles.",
    # The nine groups below were written, tested, and reachable only by invoking
    # the Click object directly. Each module's docstring said so and named the
    # registration it was owed, so this block is the debt being paid rather than
    # new surface. They are appended rather than interleaved so the diff shows
    # exactly which lines turned nine tested modules into nine reachable ones.
    #
    # Each string is kept to one rendered line on purpose. Click re-wraps a
    # group's help at the terminal width, and `test_every_active_root_parses_help`
    # asserts the whole string is present in `--help` — so a help sentence that
    # wraps is not a cosmetic difference, it is a string the inventory can no
    # longer find. The existing twenty entries all fit for the same reason.
    "advisor": "Rank reliability findings, replay incidents, and browse scenarios.",
    "boundary": "Report resilience boundaries and review candidates.",
    "risk-preview": "Preview a plan's predicted effects and the per-node blast radius.",
    "api": "Inspect the control-plane route table, OpenAPI document, and UI pages.",
    "lowlevel": "Explain the low-level primitives, their limits, and why they will not run.",
    "probe": "Author probes and stop conditions, and name what this run cannot see.",
    "schedule": "Author, review, and evaluate recurring schedules.",
    "game-day-step": "Bind scheduled drills to a game-day session and gate when they run.",
    "ha": "Promote a standby, rotate credentials, verify certificates, check updates.",
    # Appended for the reason the block above sets out: `cli/ci_cmd.py` was
    # written, tested through `CliRunner` against its own Click object, and its
    # module docstring named this registration as the debt it owed. One rendered
    # line, for the same reason as every entry here.
    "ci": "Render a pinned CI workflow and gate a pull request on mayhem's checks.",
}


COMMAND_SPECS: tuple[CommandSpec, ...] = (
    CommandSpec("campaign", "run", help_group="experiments", mutating=True),
    # `certify` is mutating because `certify run` provisions a disposable
    # container and injects a fault into it. It gates itself twice: an explicit
    # `--execute`, and the ordinary v0.9 execution-intent contract that
    # `RunEngine.execute` enforces for every other mutating surface.
    CommandSpec("certify", "run", help_group="experiments", mutating=True),
    CommandSpec("commands", "inspect", help_group="inspect"),
    CommandSpec("completion", "inspect", help_group="inspect"),
    CommandSpec("discover", "discover", help_group="discovery"),
    CommandSpec("doctor", "inspect", help_group="inspect"),
    CommandSpec("experiment", "experiment", help_group="experiments"),
    CommandSpec("extend", "extend", help_group="extension"),
    CommandSpec("game-day", "run", help_group="experiments", mutating=True),
    CommandSpec("init", "prepare", help_group="preparation"),
    CommandSpec("inspect", "inspect", help_group="inspect"),
    CommandSpec("janitor", "recover", help_group="recover", mutating=True),
    # `pack` is read-only in 1.0: `validate` and `load` both touch no
    # campaign, plan, or database, and load registers in-process only. A pack
    # fault is catalog-only, so loading a pack never mutates a target.
    CommandSpec("pack", "extend", help_group="extension"),
    CommandSpec("maniac", "run", help_group="experiments", mutating=True),
    CommandSpec("prepare", "prepare", help_group="preparation"),
    CommandSpec("recover", "recover", help_group="recover", mutating=True),
    CommandSpec("run", "run", help_group="run", mutating=True),
    # `stop` is mutating because it drives the emergency stop ladder: it freezes
    # dispatch, cancels pending leases, compensates active ones, reconciles,
    # residue-scans, verifies, and seals. It gates itself by naming the command
    # (as `recover execute` does) and, for the environment-wide scope, by the
    # plan 09 emergency role it resolves before writing anything. There is no
    # `--force` and no `--no-preflight`.
    CommandSpec("stop", "recover", help_group="recover", mutating=True),
    CommandSpec("verify", "inspect", help_group="inspect"),
    CommandSpec("bundle", "inspect", help_group="inspect"),
    # ── The nine groups that existed but were unreachable ──────────────────
    #
    # `mutating` here is a published fact, not a gate: it is what
    # `mayhem commands show` reports and what a reviewer reads before running a
    # command. So it is set from what the code can actually *do*, and the three
    # that came out `True` are the three that write or change durable state:
    #
    # * `schedule` — `add`, `enable`, `disable` and `delete` write schedule
    #   *definitions*. Its docstring is explicit that `tick` only evaluates and
    #   reports and never dispatches, but one writing subcommand is enough for
    #   the group to be mutating.
    # * `game-day-step` — `inject` creates a dispatch step, `hold`/`release`
    #   change the gate the scheduler reads at fire time, and `note` records
    #   game-day evidence. Changing a gate is a mutation even though nothing
    #   dispatches here.
    # * `ha` — `promote` takes the leadership scope and `rotate` rotates
    #   credentials. Both write to the replicated control plane.
    #
    # The other six are `False` on evidence, not on optimism: `advisor` reaches
    # `AdvisorService.submit`, which compiles and gates and approves nothing and
    # executes nothing, and whose service holds no `Store` at all; `boundary`
    # reads validated documents and prints sealed reports; `risk-preview` reads a
    # recorded run and renders pure projections; `api` projects a generated route
    # table (`serve` is deliberately not in it) and its only write is `openapi
    # --write`, which pins a documentation artifact; `lowlevel` documents that it
    # reads nothing and writes nothing, having no store, database or engine; and
    # `probe` has no `INSERT` and no store anywhere in the module.
    CommandSpec("advisor", "inspect", help_group="inspect"),
    CommandSpec("boundary", "run", help_group="experiments"),
    CommandSpec("risk-preview", "inspect", help_group="inspect"),
    CommandSpec("api", "inspect"),
    CommandSpec("lowlevel", "inspect"),
    CommandSpec("probe", "inspect"),
    # `workflow` is drawn from the existing closed vocabulary rather than widened
    # with `campaign`/`game-day`: the seven values are what `mayhem commands show`
    # groups by, and a ninth and tenth label would split a group that already has a
    # home. `schedule` and `game-day-step` are `run` because what they govern is a
    # dispatch — a schedule decides when a campaign's run fires, and a dispatch
    # step decides whether a game day's run may — which is the same workflow
    # `campaign`, `game-day` and `maniac` already declare.
    CommandSpec("schedule", "run", help_group="experiments", mutating=True),
    CommandSpec("game-day-step", "run", help_group="experiments", mutating=True),
    CommandSpec("ha", "recover", mutating=True),
    # ── The tenth group that existed but was unreachable ───────────────────
    #
    # `ci` is not mutating, and the reason is the `api openapi --write` one: the
    # only bytes it writes are the files its caller named through `--out`,
    # `--summary` and `--verdict-out`, which are rendered documents. It holds no
    # store, opens no control plane, records no approval, and dispatches
    # nothing — `check` compiles a safety case and *reports*; it does not execute.
    # A pipeline's verdict changes because this command exited non-zero, but
    # that is the exit code a gate is, not durable state mayhem wrote, and the
    # `CommitStatusPort` it would report through is unbound, so it cannot even
    # post the outcome.
    #
    # `run` and `experiments` are where `boundary` already sits: a read-only
    # gate over an authored artifact, deciding whether the run behind it may
    # proceed. `ci check` grades the plan a run would execute and renders a
    # workflow that runs it, so it belongs to that workflow and no other.
    CommandSpec("ci", "run", help_group="experiments"),
)


def register_commands(app: Any) -> None:
    from mayhem.cli.advisor_cmd import advisor
    from mayhem.cli.api_cmd import api
    from mayhem.cli.boundary_report_cmd import boundary
    from mayhem.cli.campaign import campaign
    from mayhem.cli.certify import certify
    from mayhem.cli.ci_cmd import ci
    from mayhem.cli.commands import commands
    from mayhem.cli.completion import completion
    from mayhem.cli.doctor import doctor_cmd
    from mayhem.cli.experiment import experiment
    from mayhem.cli.failover_cmd import ha
    from mayhem.cli.game_day import game_day
    from mayhem.cli.game_day_step_cmd import game_day_step
    from mayhem.cli.init import init_cmd
    from mayhem.cli.lifecycle import janitor, maniac, recover, run, verify
    from mayhem.cli.lowlevel_cmd import lowlevel
    from mayhem.cli.pack import pack
    from mayhem.cli.probe_cmd import probe
    from mayhem.cli.risk_preview_cmd import risk_preview
    from mayhem.cli.schedule_cmd import schedule
    from mayhem.cli.stop_cmd import stop
    from mayhem.cli.verify_bundle import bundle_cmd
    from mayhem.cli.workflows import discover, extend, inspect, prepare

    command_map = {
        "campaign": campaign,
        "certify": certify,
        "commands": commands,
        "completion": completion,
        "discover": discover,
        "doctor": doctor_cmd,
        "experiment": experiment,
        "game-day": game_day,
        "extend": extend,
        "init": init_cmd,
        "inspect": inspect,
        "janitor": janitor,
        "maniac": maniac,
        "pack": pack,
        "prepare": prepare,
        "recover": recover,
        "run": run,
        "stop": stop,
        "verify": verify,
        "bundle": bundle_cmd,
        # The map is keyed by the *spec* name, not by the module attribute name.
        # Two of these differ: the attribute is `risk_preview` and
        # `game_day_step` for a command the user types `risk-preview` and
        # `game-day-step`. `app.add_command` registers under `command.name`, so
        # the two spellings have to agree or the command lands under a name the
        # user cannot type.
        "advisor": advisor,
        "boundary": boundary,
        "risk-preview": risk_preview,
        "api": api,
        "lowlevel": lowlevel,
        "probe": probe,
        "schedule": schedule,
        "game-day-step": game_day_step,
        "ha": ha,
        "ci": ci,
    }
    for spec in COMMAND_SPECS:
        command = command_map[spec.name]
        command.help = COMMAND_HELP[spec.name]
        app.add_command(command)
