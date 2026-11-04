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
