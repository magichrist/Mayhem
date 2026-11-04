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
