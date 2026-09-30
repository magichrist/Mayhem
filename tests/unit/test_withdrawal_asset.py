"""Pins the audited truth about the plan 06 §6 asset.

`docs/v1.0.0/06-debt-and-quality.md` §6 is titled "`withdrawal` audit — the one
asset with no plan". The audit (`docs/v1.0.0/08-withdrawal-audit.md`) found that
no `withdrawal` asset exists anywhere in the working tree, and that the section
body is actually about the evidence bundle — which is declared buildable and is
not.

Every assertion below is true as of that audit. Each one is a pin, not a wish:
when the corresponding capability is implemented, the assertion must be
inverted or deleted in the same change that implements it.

INVERSION NOTES
---------------
* `test_no_withdrawal_command_is_dispatchable` — invert the moment a
  `withdrawal` command or subcommand is registered.
* `test_no_withdrawal_fault_is_catalogued` — invert the moment a fault id
  containing "withdraw" enters `CATALOG`.
* `test_bundle_group_advertises_build_it_cannot_do` — this test is the defect
  report. It fails when `mayhem bundle build` exists, and at that point the
  assertions should be replaced by "the group help matches its subcommands".
* `test_build_bundle_has_no_production_caller` — the day a producer lands
  (the planned `mayhem bundle build RUN_ID`), this becomes a positive test that
  the producer calls `build_bundle`.
"""

from __future__ import annotations

from pathlib import Path

import click

from mayhem.cli.app import app
from mayhem.cli.command_registry import COMMAND_HELP
from mayhem.domain.catalog import all_definitions

SRC = Path(__file__).parents[2] / "src" / "mayhem"

#: Files allowed to mention `build_bundle` in non-test source. The definition
#: itself, and the IO module's docstring pointing at it.
#: Modules permitted to reference `build_bundle`: the definition, its IO
#: layer, and the `mayhem bundle build` producer. Anything else is caught.
_BUILD_BUNDLE_MODULES = frozenset(
    {
        "domain/evidence_bundle.py",
        "infra/evidence_bundle_io.py",
        "cli/verify_bundle.py",
    }
)

#: The module that *defines* the producer. A caller is any other listed module
#: that actually invokes `build_bundle(`.
_BUILD_BUNDLE_DEFINITION = frozenset({"domain/evidence_bundle.py"})


def _dispatchable_names() -> set[str]:
    """Every command and subcommand the CLI will actually route to."""
    found: set[str] = set()

    def walk(group: click.Group, prefix: tuple[str, ...] = ()) -> None:
        for name, command in sorted((group.commands or {}).items()):
            found.add(" ".join((*prefix, name)))
            if isinstance(command, click.Group):
                walk(command, (*prefix, name))

    walk(app)
    return found


def test_no_withdrawal_command_is_dispatchable() -> None:
    names = _dispatchable_names()
    assert names, "the CLI exposes no commands; the probe is broken, not the code"
    assert not [name for name in names if "withdraw" in name.lower()]


def test_no_withdrawal_fault_is_catalogued() -> None:
    definitions = all_definitions()
    assert len(definitions) == 141, "catalogue size moved; re-read the audit"
    assert not [d.id for d in definitions if "withdraw" in d.id.lower()]


def test_bundle_group_now_advertises_only_what_it_can_do() -> None:
    """INVERTED from the pin that caught the original overclaim.

    The `bundle` group used to say "Build and verify" while offering only
    `show` and `verify` — mayhem shipped a verifier for bundles it could not
    produce, and named the missing producer in its own `--help`. `bundle build`
    now exists, so the advertised string is finally true.

    This assertion is the *other half* of the gate: should `build` ever be
    removed again, the help string must be narrowed in the same change, and
    this test fails until it is.
    """
    bundle = app.commands["bundle"]
    assert isinstance(bundle, click.Group)
    subcommands = set(bundle.commands or {})
    assert subcommands == {"build", "show", "verify"}
    assert COMMAND_HELP["bundle"] == "Build and verify portable evidence bundles."
    assert bundle.help == "Build and verify portable evidence bundles."


def test_build_bundle_has_a_production_caller() -> None:
    """INVERTED from the pin that recorded the missing producer.

    `build_bundle` had zero callers outside `tests/`; the producer existed only
    as a library function nothing invoked. `mayhem bundle build` is now that
    caller. The allowlist is still checked, so an *unlisted* second producer
    appearing is still caught.
    """
    offenders = [
        path.relative_to(SRC).as_posix()
        for path in sorted(SRC.rglob("*.py"))
        if "build_bundle" in path.read_text(encoding="utf-8")
        and path.relative_to(SRC).as_posix() not in _BUILD_BUNDLE_MODULES
    ]
    assert not offenders, f"an unexpected producer appeared: {offenders}"
    callers = [
        path.relative_to(SRC).as_posix()
        for path in sorted(SRC.rglob("*.py"))
        if "build_bundle(" in path.read_text(encoding="utf-8")
        and path.relative_to(SRC).as_posix() not in _BUILD_BUNDLE_DEFINITION
    ]
    assert callers, "the producer lost its caller; mayhem cannot build a bundle again"
