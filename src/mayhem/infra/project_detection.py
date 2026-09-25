from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

COMPOSE_CANDIDATES = ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml")
MAYHEM_CANDIDATES = ("mayhem.yaml", "mayhem.yml")
K8S_KINDS = {
    "Deployment",
    "StatefulSet",
    "DaemonSet",
    "Service",
    "Pod",
    "Job",
    "CronJob",
    "ReplicaSet",
    "ConfigMap",
    "Ingress",
}


@dataclass(frozen=True, slots=True)
class DetectionResult:
    compose_files: tuple[Path, ...]
    mayhem_yaml: Path | None
    k8s_manifests: tuple[Path, ...]
    explicit_engine: str | None
    has_compose: bool
    has_mayhem_config: bool
    has_k8s_manifest: bool


def find_compose_files(directory: Path) -> tuple[Path, ...]:
    found: list[Path] = []
    for name in COMPOSE_CANDIDATES:
        p = directory / name
        if p.is_file():
            found.append(p)
    return tuple(found)


def find_mayhem_yaml(directory: Path) -> Path | None:
    for name in MAYHEM_CANDIDATES:
        p = directory / name
        if p.is_file():
            return p
    return None


def _is_k8s_manifest(path: Path) -> bool:
    try:
        data = yaml.safe_load(path.read_text()) or {}
    except Exception:
        return False
    if not isinstance(data, dict):
        return False
    kind = data.get("kind")
    api = data.get("apiVersion")
    return bool(isinstance(kind, str) and kind in K8S_KINDS and isinstance(api, str))


def find_k8s_manifests(directory: Path) -> tuple[Path, ...]:
    manifests: list[Path] = []
    for pattern in ("*.yaml", "*.yml"):
        for p in directory.glob(pattern):
            if p.name in COMPOSE_CANDIDATES or p.name in MAYHEM_CANDIDATES:
                continue
            if _is_k8s_manifest(p):
                manifests.append(p)
    for sub in ("k8s", "manifests", "kubernetes", "k8s-manifests"):
        subdir = directory / sub
        if subdir.is_dir():
            for pattern in ("*.yaml", "*.yml"):
                for p in subdir.glob(pattern):
                    if _is_k8s_manifest(p):
                        manifests.append(p)
    return tuple(sorted(set(manifests)))


def detect_explicit_engine(directory: Path) -> str | None:
    mayhem_path = find_mayhem_yaml(directory)
    if mayhem_path is None:
        return None
    try:
        data = yaml.safe_load(mayhem_path.read_text()) or {}
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    runtime = data.get("runtime")
    if isinstance(runtime, str) and runtime in ("docker", "podman", "kubernetes"):
        return runtime
    kube = data.get("kubernetes")
    if isinstance(kube, dict) and kube:
        return "kubernetes"
    return None


def detect_project(directory: str | Path | None = None) -> DetectionResult:
    base = Path(directory) if directory is not None else Path.cwd()
    compose_files = find_compose_files(base)
    mayhem_yaml = find_mayhem_yaml(base)
    k8s_manifests = find_k8s_manifests(base)
    explicit_engine = detect_explicit_engine(base)
    return DetectionResult(
        compose_files=compose_files,
        mayhem_yaml=mayhem_yaml,
        k8s_manifests=k8s_manifests,
        explicit_engine=explicit_engine,
        has_compose=len(compose_files) > 0,
        has_mayhem_config=mayhem_yaml is not None,
        has_k8s_manifest=len(k8s_manifests) > 0,
    )
