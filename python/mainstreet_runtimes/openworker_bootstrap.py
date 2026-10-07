from __future__ import annotations

from typing import Any, Mapping

from .openworker_adapter import OpenWorkerProposalAdapter
from .openworker_context import OpenWorkerProductionContextStore
from .openworker_ipc import OpenWorkerClaimSieveHTTPSClient
from .openworker_native_bridge import guarded_turn_engine_class, verify_pinned_openworker_runtime


class OpenWorkerBootstrapError(RuntimeError):
    pass


def _native_primary_constructor() -> tuple[Any, Any]:
    verify_pinned_openworker_runtime()
    import coworker.agent as agent_module
    import coworker.engine as engine_module

    if agent_module.TurnEngine is not engine_module.TurnEngine:
        raise OpenWorkerBootstrapError(
            "OpenWorker primary TurnEngine constructor was already modified; refusing ambiguous guard binding"
        )
    return agent_module, engine_module


def install_production_runtime_guard(
    client: OpenWorkerClaimSieveHTTPSClient,
    context_store: OpenWorkerProductionContextStore,
    *,
    consequential_tools: set[str] | frozenset[str] | None = None,
    native_tool_map: Mapping[str, str] | None = None,
) -> type:
    """Bind the real primary OpenWorker engine to mTLS ClaimSieve with per-call context.

    Every engine instance receives its own adapter whose context provider closes over that
    engine. At tool-execution time OpenWorker has already populated `engine.audit_context`
    with the actual session id; a durable monotonic context store allocates the request
    sequence and derives trace/campaign/work-item identities. No process-wide fixture
    context or caller-supplied route callback exists on this production path.
    """

    if not isinstance(client, OpenWorkerClaimSieveHTTPSClient):
        raise OpenWorkerBootstrapError("production guard requires the fixed mTLS ClaimSieve client")
    if not isinstance(context_store, OpenWorkerProductionContextStore):
        raise OpenWorkerBootstrapError("production guard requires the durable context store")

    agent_module, _ = _native_primary_constructor()
    Guarded = guarded_turn_engine_class()
    frozen_map = dict(native_tool_map or {})

    class ProductionClaimSieveOpenWorkerTurnEngine(Guarded):
        __claimsieve_production_guard__ = True

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            if "claimsieve_adapter" in kwargs or "native_tool_map" in kwargs:
                raise OpenWorkerBootstrapError(
                    "upstream OpenWorker may not override production ClaimSieve guard dependencies"
                )

            def context_for(tool_call: Mapping[str, Any]):
                return context_store.context_for_engine_call(self, tool_call)

            adapter = OpenWorkerProposalAdapter(
                context_for,
                client.route_intent,
                consequential_tools=consequential_tools,
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


def install_test_turn_engine_guard(
    adapter: OpenWorkerProposalAdapter,
    *,
    native_tool_map: Mapping[str, str] | None = None,
) -> type:
    """Reference-only binding for focused tests that already own an adapter callback."""

    agent_module, _ = _native_primary_constructor()
    Guarded = guarded_turn_engine_class()
    frozen_map = dict(native_tool_map or {})

    class TestClaimSieveOpenWorkerTurnEngine(Guarded):
        __claimsieve_production_guard__ = False

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(
                *args,
                claimsieve_adapter=adapter,
                native_tool_map=frozen_map,
                **kwargs,
            )

    agent_module.TurnEngine = TestClaimSieveOpenWorkerTurnEngine
    return TestClaimSieveOpenWorkerTurnEngine


def verify_production_turn_engine_guard_installed() -> None:
    import coworker.agent as agent_module

    engine_class = getattr(agent_module, "TurnEngine", None)
    if not bool(getattr(engine_class, "__claimsieve_production_guard__", False)):
        raise OpenWorkerBootstrapError(
            "OpenWorker production guard is not installed in coworker.agent.build_engine"
        )
