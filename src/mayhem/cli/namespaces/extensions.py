"""``extensions`` namespace: fault packs, marketplace, sandbox."""

from __future__ import annotations

from mayhem.cli.marketplace_cmd import marketplace
from mayhem.cli.pack import pack
from mayhem.cli.resolver import make_group
from mayhem.cli.sandbox_cmd import sandbox

extensions = make_group(
    "extensions",
    "Manage packs, marketplace and sandbox features.",
)

extensions.add_command(pack)
extensions.add_command(marketplace)
extensions.add_command(sandbox)
