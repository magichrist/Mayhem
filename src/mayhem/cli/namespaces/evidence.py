"""``evidence`` namespace: bundles, verification, safety proofs."""

from __future__ import annotations

import click

from mayhem.cli.resolver import make_group
from mayhem.cli.verify_bundle import bundle_cmd
from mayhem.cli.lifecycle import verify as verify_cmd
from mayhem.cli.proof_cmd import prove


evidence = make_group(
    "evidence",
    "Export, verify and inspect evidence and proofs.",
)

# `bundle` is itself a group; carry over all its existing subcommands intact.
bundle_cmd.name = "bundle"
evidence.add_command(bundle_cmd)

# `verify` (standalone command, distinct from bundle verify) lives directly under evidence.
evidence.add_command(verify_cmd, name="verify")

evidence.add_command(prove)
