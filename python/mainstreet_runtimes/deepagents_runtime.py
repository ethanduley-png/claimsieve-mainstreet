from __future__ import annotations

import copy
from collections.abc import Callable, Sequence
from typing import Any

from deepagents import create_deep_agent
from deepagents.backends import StateBackend
from langchain.agents.middleware.types import AgentMiddleware
from langchain_core.language_models import BaseChatModel
from langchain_core.tools import BaseTool

from mainstreet_runtimes.deepagents_adapter import DeepAgentsProposalAdapter
from mainstreet_runtimes.deepagents_middleware import ClaimSieveDeepAgentsMiddleware


class DeepAgentsRuntimeSafetyError(ValueError):
    """Raised when a Deep Agents configuration can bypass the governed tool path."""


def _middleware_name(value: Any) -> str | None:
    name = getattr(value, "name", None)
    return name if isinstance(name, str) else None


def _tool_name(value: BaseTool | Callable[..., Any] | dict[str, Any]) -> str | None:
    if isinstance(value, dict):
        name = value.get("name")
        return name if isinstance(name, str) and name else None
    name = getattr(value, "name", None)
    if isinstance(name, str) and name:
        return name
    function_name = getattr(value, "__name__", None)
    return function_name if isinstance(function_name, str) and function_name else None


def _guard_middleware_list(
    middleware: Sequence[AgentMiddleware[Any, Any, Any]] | None,
) -> list[AgentMiddleware[Any, Any, Any]]:
    selected = list(middleware or [])
    if any(_middleware_name(item) == ClaimSieveDeepAgentsMiddleware.name for item in selected):
        raise DeepAgentsRuntimeSafetyError(
            "caller middleware may not replace or shadow ClaimSieveDeepAgentsMiddleware"
        )
    return selected


def _validate_tool_classification(
    tools: Sequence[BaseTool | Callable[..., Any] | dict[str, Any]] | None,
    adapter: DeepAgentsProposalAdapter,
    allowed_benign_tool_names: frozenset[str],
) -> None:
    for tool in tools or []:
        name = _tool_name(tool)
        if name is None:
            raise DeepAgentsRuntimeSafetyError(
                "every caller-supplied tool must expose a stable non-empty name"
            )
        if adapter.is_consequential(name):
            continue
        if name in allowed_benign_tool_names:
            continue
        raise DeepAgentsRuntimeSafetyError(
            f"unclassified caller-supplied tool is denied in governed mode: {name}"
        )


def prepare_governed_subagents(
    *,
    tools: Sequence[BaseTool | Callable[..., Any] | dict[str, Any]] | None,
    adapter: DeepAgentsProposalAdapter,
    allowed_benign_tool_names: set[str] | frozenset[str] | None = None,
    subagents: Sequence[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Return raw subagent specs with a ClaimSieve gate on every tool path.

    Governed mode rejects compiled and remote async subagents because their
    internal middleware/tool path is not controlled by this process. Raw
    subagents are copied and receive a fresh ClaimSieve middleware instance.

    Caller-supplied tools are fail-closed: each stable tool name must be either
    configured as consequential on the adapter or explicitly listed as benign.

    An explicit `general-purpose` subagent is always supplied so Deep Agents
    does not auto-create its default general-purpose subagent without our custom
    middleware.
    """

    benign = frozenset(allowed_benign_tool_names or ())
    if any(not isinstance(name, str) or not name for name in benign):
        raise DeepAgentsRuntimeSafetyError("benign tool names must be non-empty strings")
    overlap = benign.intersection(adapter.consequential_tools)
    if overlap:
        raise DeepAgentsRuntimeSafetyError(
            "a tool cannot be classified as both benign and consequential: "
            + ",".join(sorted(overlap))
        )
    _validate_tool_classification(tools, adapter, benign)

    prepared: list[dict[str, Any]] = []
    saw_general_purpose = False

    for original in subagents or []:
        if not isinstance(original, dict):
            raise DeepAgentsRuntimeSafetyError("subagent specs must be dictionaries")
        if "graph_id" in original:
            raise DeepAgentsRuntimeSafetyError(
                "remote async subagents are disabled in governed mode"
            )
        if "runnable" in original:
            raise DeepAgentsRuntimeSafetyError(
                "compiled subagents are disabled in governed mode"
            )
        name = original.get("name")
        if not isinstance(name, str) or not name:
            raise DeepAgentsRuntimeSafetyError("raw subagents require a non-empty name")
        if name == "general-purpose":
            saw_general_purpose = True

        spec = copy.deepcopy(original)
        if "tools" in spec:
            subagent_tools = spec.get("tools")
            if not isinstance(subagent_tools, Sequence) or isinstance(subagent_tools, (str, bytes)):
                raise DeepAgentsRuntimeSafetyError("raw subagent tools must be a sequence")
            _validate_tool_classification(subagent_tools, adapter, benign)
        caller_middleware = _guard_middleware_list(spec.get("middleware"))
        spec["middleware"] = [
            *caller_middleware,
            ClaimSieveDeepAgentsMiddleware(adapter),
        ]
        prepared.append(spec)

    if not saw_general_purpose:
        prepared.insert(
            0,
            {
                "name": "general-purpose",
                "description": (
                    "General-purpose proposal agent. Consequential tool calls "
                    "must route through ClaimSieve before any execution boundary."
                ),
                "system_prompt": (
                    "Perform research and planning. Treat consequential tool "
                    "results as ClaimSieve routing receipts, not proof that an "
                    "external action occurred."
                ),
                "tools": list(tools or []),
                "middleware": [ClaimSieveDeepAgentsMiddleware(adapter)],
            },
        )

    return prepared


def create_claimsieve_deep_agent(
    *,
    model: str | BaseChatModel,
    adapter: DeepAgentsProposalAdapter,
    tools: Sequence[BaseTool | Callable[..., Any] | dict[str, Any]] | None = None,
    allowed_benign_tool_names: set[str] | frozenset[str] | None = None,
    system_prompt: str | None = None,
    middleware: Sequence[AgentMiddleware[Any, Any, Any]] | None = None,
    subagents: Sequence[dict[str, Any]] | None = None,
    **kwargs: Any,
):
    """Create a Deep Agent with ClaimSieve on main-agent and subagent tool paths.

    The wrapper fixes the backend to `StateBackend`, which does not provide the
    sandbox command execution capability required by Deep Agents' `execute`
    tool. Production provider access belongs behind the separate ClaimSieve
    restricted executor, not inside this agent.
    """

    if "backend" in kwargs:
        raise DeepAgentsRuntimeSafetyError(
            "governed mode fixes the Deep Agents backend to StateBackend"
        )
    if "middleware" in kwargs or "subagents" in kwargs:
        raise DeepAgentsRuntimeSafetyError("duplicate governed runtime configuration")

    benign = frozenset(allowed_benign_tool_names or ())
    caller_middleware = _guard_middleware_list(middleware)
    gate = ClaimSieveDeepAgentsMiddleware(adapter)
    governed_subagents = prepare_governed_subagents(
        tools=tools,
        adapter=adapter,
        allowed_benign_tool_names=benign,
        subagents=subagents,
    )

    return create_deep_agent(
        model=model,
        tools=tools,
        system_prompt=system_prompt,
        middleware=[*caller_middleware, gate],
        subagents=governed_subagents,
        backend=StateBackend(),
        **kwargs,
    )
