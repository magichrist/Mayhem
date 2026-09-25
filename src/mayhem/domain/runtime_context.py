"""``RuntimeContext`` — the runtime resolved once per plan (v0.9.0).

Before v0.9.0 every stage of a run re-derived *where* it was running: the CLI
resolved an engine string for planning, another layer re-resolved it for
preflight, and the executor re-resolved it again when touching containers. Each
seam could disagree, so a plan compiled against one engine could execute against
another.

:class:`RuntimeContext` is the frozen record of that decision. It is resolved
**once** during application preflight (see
:func:`mayhem.cli.services.resolve_runtime_context`) and then carried unchanged
through planning, preflight, and execution.

This module is deliberately a *pure* value model plus one pure invariant
helper: it imports nothing from ``mayhem`` except the domain's own error type,
so the domain never depends on the runtime adapters, topology providers, or CLI
services that produce and consume it.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from mayhem.domain.errors import InvariantViolationError


class RuntimeContext(BaseModel):
    """Immutable record of the resolved runtime for one plan.

    Attributes:
        engine: ``"docker"``, ``"podman"``, or ``"kubernetes"``. Resolved once;
            never re-derived downstream.
        target_profile: Name of the selected target profile, when one was
            selected (``--target`` / the config's single default profile).
        namespace: Kubernetes namespace, resolved from the target profile.
            ``None`` for container engines.
        context: kubeconfig context, resolved from the target profile. ``None``
            for container engines.
        runtime_version: Engine-reported version string, when the engine
            binary could be probed. ``None`` when unknown — never guessed.
        provider_version: Version of the topology/discovery provider backing
            the engine (the Kubernetes SDK for ``kubernetes``). ``None`` for
            container engines, which have no versioned provider SDK.
        topology_fingerprint: Fingerprint of the graph this context was
            resolved against, so the handoff into execution can be proven to
            describe the same topology that was planned.
    """

    model_config = ConfigDict(frozen=True)

    engine: str
    target_profile: str | None = None
    namespace: str | None = None
    context: str | None = None
    runtime_version: str | None = None
    provider_version: str | None = None
    topology_fingerprint: str | None = None

    @property
    def is_kubernetes(self) -> bool:
        return self.engine == "kubernetes"

    def to_dict(self) -> dict[str, str | None]:
        return {
            "engine": self.engine,
            "target_profile": self.target_profile,
            "namespace": self.namespace,
            "context": self.context,
            "runtime_version": self.runtime_version,
            "provider_version": self.provider_version,
            "topology_fingerprint": self.topology_fingerprint,
        }


def reconcile_engine(engine: str | None, runtime: RuntimeContext | None) -> str | None:
    """Reconcile a caller-supplied engine name with a resolved runtime context.

    This is the one place the "one resolved context per plan" rule is enforced,
    so the planner, the preflight, and the executor cannot drift onto different
    runtimes. It is pure: no probing, no IO, no adapters.

    * Neither supplied → ``None`` ("unspecified"; the caller applies its own
      compatibility default).
    * Only one supplied → that one. A ``None`` or blank engine means
      *unspecified*, never a disagreement.
    * Both supplied and equal → the engine.
    * Both supplied and different → ``InvariantViolationError``
      (``runtime_engine_mismatch``), raised before any planning, safety
      validation, or lease work happens.
    """
    specified = engine if (engine or "").strip() else None
    if runtime is None:
        return specified
    if specified is None:
        return runtime.engine
    if specified != runtime.engine:
        raise InvariantViolationError(
            "runtime_engine_mismatch",
            f"engine {specified!r} disagrees with the resolved runtime "
            f"{runtime.engine!r}; resolve one runtime context per plan",
        )
    return runtime.engine
