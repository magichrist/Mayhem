"""``orchestration`` namespace: campaigns, schedules, and game days."""

from __future__ import annotations

import copy

from mayhem.cli.campaign import campaign
from mayhem.cli.game_day import game_day
from mayhem.cli.game_day_step_cmd import game_day_step
from mayhem.cli.resolver import make_group
from mayhem.cli.schedule_cmd import schedule

orchestration = make_group(
    "orchestration",
    "Manage campaigns, schedules and game days.",
)

orchestration.add_command(campaign)
orchestration.add_command(schedule)

# `game-day` is a group; `game-day-step` becomes `game-day step` under it.
game_day = copy.copy(game_day)
game_day.name = "game-day"
orchestration.add_command(game_day)

# The old `game-day-step` command is rehomed as a subcommand of `game-day`.
game_day_step = copy.copy(game_day_step)
game_day_step.name = "step"
game_day.add_command(game_day_step)
