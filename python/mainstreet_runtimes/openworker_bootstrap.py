from __future__ import annotations

from typing import Any, Mapping

from .openworker_adapter import OpenWorkerProposalAdapter
from .openworker_native_bridge import (
    OpenWorkerNativeBridgeError,
    guarded_turn_engine_class,
    verify_pinned_openworker_runtime,
)


class OpenWorkerBootstrapError(RuntimeError):
    pass


def install_production_turn_engine_guard(
    adapter: OpenWorkerProposalAdapter,
    *,
    native_tool_map: Mapping[str, str] | None = None,
) -> type:
    """Bind ClaimSieve into OpenWorker's real primary engine construction seam.

    The pinned OpenWorker `coworker.agent.build_engine` resolves its module-global
    `TurnEngine` when each engine is built. Upstream exposes no engine-factory hook at this
    commit. We therefore replace exactly that one symbol after verifying the pinned runtime
    and refuse to install if any other code has already changed the constructor.

    The read-only `explore` subagent has its own direct TurnEngine import and is deliberately
    not rebound: at this pin its registry contains only read/search/git tools and its
    PermissionEngine is Mode.PLAN.
    """

    verify_pinned_openworker_runtime()
    import coworker.agent as agent_module
    import coworker.engine as engine_module

    if agent_module.TurnEngine is not engine_module.TurnEngine:
        raise OpenWorkerBootstrapError(
            "OpenWorker primary TurnEngine constructor was already modified; refusing ambiguous guard binding"
        )

    Guarded = guarded_turn_engine_class()
    frozen_map = dict(native_tool_map or {})

    class ProductionClaimSieveOpenWorkerTurnEngine(Guarded):
        __claimsieve_production_guard__ = True

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            if "claimsieve_adapter" in kwargs or "native_tool_map" in kwargs:
                raise OpenWorkerBootstrapError(
                    "upstream OpenWorker may not override production ClaimSieve guard dependencies"
                )
            super().__init__(
                *args,
                claimsieve_adapter=adapter,
                native_tool_map=frozen_map,
                **kwargs,
            )

    agent_module.TurnEngine = ProductionClaimSieveOpenWorkerTurnEngine
    if agent_module.TurnEngine is not ProductionClaimSieveOpenWorkerTurnEngine:
        raise OpenWorkerBootstrapError("OpenWorker primary guard binding did not take effect")
    return ProductionClaimSieveOpenWorkerTurnEngine


def verify_production_turn_engine_guard_installed() -> None:
    import coworker.agent as agent_module

    engine_class = getattr(agent_module, "TurnEngine", None)
    if not bool(getattr(engine_class, "__claimsieve_production_guard__", False)):
        raise OpenWorkerBootstrapError(
            "OpenWorker production guard is not installed in coworker.agent.build_engine"
        )
