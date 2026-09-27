from __future__ import annotations

import argparse
import hashlib
import tarfile
import zipfile
from email.parser import Parser
from pathlib import Path


def _fail(results: list[tuple[str, str, str]], name: str, detail: str) -> None:
    results.append((name, "FAIL", detail))


def _pass(results: list[tuple[str, str, str]], name: str, detail: str = "") -> None:
    results.append((name, "PASS", detail))


def verify(dist: Path) -> list[tuple[str, str, str]]:
    results: list[tuple[str, str, str]] = []
    wheels = sorted(dist.glob("mayhem_cli-*.whl"))
    sdists = sorted(dist.glob("mayhem_cli-*.tar.gz"))
    if len(wheels) != 1:
        _fail(results, "wheel-count", f"expected 1 wheel, found {len(wheels)}")
    else:
        _pass(results, "wheel-count")
    if len(sdists) != 1:
        _fail(results, "sdist-count", f"expected 1 sdist, found {len(sdists)}")
    else:
        _pass(results, "sdist-count")
    if not wheels:
        return results
    wheel = wheels[0]
    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
        metadata_name = next((name for name in names if name.endswith(".dist-info/METADATA")), None)
        entry_name = next(
            (name for name in names if name.endswith(".dist-info/entry_points.txt")), None
        )
        if metadata_name is None:
            _fail(results, "wheel-metadata", "METADATA missing")
            return results
        metadata = Parser().parsestr(archive.read(metadata_name).decode())
        if metadata.get("Name") != "mayhem-cli":
            _fail(results, "distribution-name", str(metadata.get("Name")))
        else:
            _pass(results, "distribution-name")
        requires = metadata.get_all("Requires-Dist") or []
        if not any(item.startswith("kubernetes") and "extra ==" not in item for item in requires):
            _fail(results, "kubernetes-default", "kubernetes is not an unconditional dependency")
        else:
            _pass(results, "kubernetes-default")
        if metadata.get_all("Provides-Extra"):
            _fail(results, "no-extras", "unexpected optional extras")
        else:
            _pass(results, "no-extras")
        if (
            entry_name is None
            or "mayhem = mayhem.cli.app:main" not in archive.read(entry_name).decode()
        ):
            _fail(results, "console-scripts", "mayhem entry point missing")
        else:
            _pass(results, "console-scripts")
        required = {"mayhem/cli/app.py", "mayhem/schemas/output_v1.json"}
        missing = sorted(item for item in required if item not in names)
        if missing:
            _fail(results, "wheel-contents", ", ".join(missing))
        else:
            _pass(results, "wheel-contents")
    if sdists:
        with tarfile.open(sdists[0]) as archive:
            names = set(archive.getnames())
            if not any(name.endswith("PKG-INFO") for name in names):
                _fail(results, "sdist-contents", "PKG-INFO missing")
            else:
                _pass(results, "sdist-contents")
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    _pass(results, "wheel-sha256", digest)
    return results


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("dist", type=Path)
    args = parser.parse_args()
    results = verify(args.dist)
    for name, status, detail in results:
        suffix = f": {detail}" if detail else ""
        print(f"{status:<4} {name}{suffix}")
    return 0 if all(status == "PASS" for _, status, _ in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
