"""Plan 20 Phase 3 — upgrade channels (enterprise feature: upgrade channels).

Three channels, as data rather than branches: ``stable`` (default, vetted
releases), ``extended`` (security-fix only, for regulated sites), and
``rapid`` (every release, for pre-production rehearsal). The channel answers
two questions and refuses two mistakes:

* which versions may this install move to — answered by
  :func:`validate_upgrade`, which refuses a downgrade by name
  (``upgrade.downgrade_refused``) and an unparseable version
  (``upgrade.unparseable_version``);
* which channels may this install even follow — an air-gapped site cannot
  follow ``rapid``, because rapid assumes egress the site does not have
  (``upgrade.air_gapped_channel``).

Pure types and pure refusals, in the Phase-1 style: no network, no clock, no
package manager. The installer reads the answer; this module only decides
whether the declared move is admissible.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from mayhem.domain.deployment import DeploymentModel

__all__ = [
    "RULE_UPGRADE_AIR_GAPPED_CHANNEL",
    "RULE_UPGRADE_DOWNGRADE_REFUSED",
    "RULE_UPGRADE_UNPARSEABLE_VERSION",
    "UPGRADE_CHANNELS",
    "UpgradeChannel",
    "UpgradeDescriptor",
    "parse_version",
    "upgrade_channel",
    "validate_upgrade",
]


class UpgradeChannel(StrEnum):
    """The release cadence an install follows."""

    STABLE = "stable"
    EXTENDED = "extended"
    RAPID = "rapid"


RULE_UPGRADE_DOWNGRADE_REFUSED = "upgrade.downgrade_refused"
RULE_UPGRADE_UNPARSEABLE_VERSION = "upgrade.unparseable_version"
RULE_UPGRADE_AIR_GAPPED_CHANNEL = "upgrade.air_gapped_channel"


@dataclass(frozen=True, slots=True)
class UpgradeDescriptor:
    """What following a channel means, as data."""

    channel: UpgradeChannel
    summary: str
    cadence: str
    requires_egress: bool
    supports_air_gapped: bool


UPGRADE_CHANNELS: Final[tuple[UpgradeDescriptor, ...]] = (
    UpgradeDescriptor(
        channel=UpgradeChannel.STABLE,
        summary="Vetted releases; the default for every deployment model",
        cadence="per minor release",
        requires_egress=True,
        supports_air_gapped=True,
    ),
    UpgradeDescriptor(
        channel=UpgradeChannel.EXTENDED,
        summary="Security fixes only; for regulated sites that pin a minor",
        cadence="per patch release",
        requires_egress=True,
        supports_air_gapped=True,
    ),
    UpgradeDescriptor(
        channel=UpgradeChannel.RAPID,
        summary="Every release including pre-releases; rehearsal sites only",
        cadence="per release",
        requires_egress=True,
        supports_air_gapped=False,
    ),
)

_CHANNELS_BY_NAME: Final[dict[str, UpgradeDescriptor]] = {
    descriptor.channel.value: descriptor for descriptor in UPGRADE_CHANNELS
}


def upgrade_channel(name: str) -> UpgradeDescriptor:
    """Look a channel up by name; unknown names are planning errors."""
    try:
        return _CHANNELS_BY_NAME[name.strip().lower()]
    except KeyError:
        known = ", ".join(sorted(_CHANNELS_BY_NAME))
        msg = f"upgrade channel {name!r} is not defined (known: {known})"
        raise LookupError(msg) from None


def parse_version(value: str) -> tuple[int, ...]:
    """Parse ``major.minor.patch`` (trailing parts optional) into ints.

    Raises:
        ValueError: ``[upgrade.unparseable_version]`` when the value is not a
            dotted numeric version. A version the parser guesses at is a
            version comparison nobody can review.
    """
    candidate = value.strip().lstrip("v")
    parts = candidate.split(".")
    if (
        not parts
        or not candidate
        or any(
            not part.isdigit()
            or (part != str(int(part)) and part.startswith("0") and len(part) > 1)
            for part in parts
        )
    ):
        raise ValueError(
            f"[{RULE_UPGRADE_UNPARSEABLE_VERSION}] version {value!r} is not a "
            "dotted numeric version such as '1.1.0'"
        )
    try:
        return tuple(int(part) for part in parts)
    except ValueError:
        raise ValueError(
            f"[{RULE_UPGRADE_UNPARSEABLE_VERSION}] version {value!r} is not a "
            "dotted numeric version such as '1.1.0'"
        ) from None


def validate_upgrade(
    channel: UpgradeChannel | str,
    current: str,
    target: str,
    *,
    model: DeploymentModel | None = None,
) -> str:
    """Why the move ``current`` → ``target`` on ``channel`` is inadmissible, or ``""``.

    Three refusals: an air-gapped install following a channel that assumes
    egress, an unparseable version on either side, and a downgrade. Staying on
    the same version is admissible (a no-op upgrade is idempotent, not wrong).
    """
    name = channel.value if isinstance(channel, UpgradeChannel) else str(channel)
    try:
        descriptor = upgrade_channel(name)
    except LookupError as exc:
        return f"upgrade.unknown_channel: {exc}"
    if model is DeploymentModel.AIR_GAPPED and not descriptor.supports_air_gapped:
        return (
            f"{RULE_UPGRADE_AIR_GAPPED_CHANNEL}: channel {descriptor.channel.value!r} "
            f"assumes egress ({descriptor.cadence}) but this install is the air-gapped "
            "deployment model. Upgrades arrive as offline bundles on the stable or "
            "extended channel, never over a network the site does not have"
        )
    try:
        have = parse_version(current)
    except ValueError as exc:
        return str(exc)
    try:
        want = parse_version(target)
    except ValueError as exc:
        return str(exc)
    # Compare on equal-length tuples so "1.10" and "1.10.0" agree.
    width = max(len(have), len(want))
    have_padded = have + (0,) * (width - len(have))
    want_padded = want + (0,) * (width - len(want))
    if want_padded < have_padded:
        return (
            f"{RULE_UPGRADE_DOWNGRADE_REFUSED}: {target!r} is older than the "
            f"installed {current!r} on channel {descriptor.channel.value!r}. "
            "Downgrades are refused rather than applied: stored evidence sealed "
            "under a newer version must never be re-opened by an older binary"
        )
    return ""
