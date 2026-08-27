from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from typing import Any

from langchain.agents.middleware.types import AgentMiddleware
from langchain_core.messages import ToolMessage
from langgraph.prebuilt.tool_node import ToolCallRequest
from langgraph.types import Command

from mainstreet_runtimes.deepagents_adapter import DeepAgentsProposalAdapter


class ClaimSieveDeepAgentsMiddleware(AgentMiddleware[Any, Any, Any]):
    """Route configured consequential tool calls to ClaimSieve before execution.

    For consequential tools this middleware deliberately does not invoke the
    underlying Deep Agents tool handler. The returned ToolMessage confirms only
    that the proposal was routed to ClaimSieve. It is not evidence that the
    external action occurred.
    """

    name = "ClaimSieveDeepAgentsMiddleware"

    def __init__(self, adapter: DeepAgentsProposalAdapter) -> None:
        self._adapter = adapter

    @staticmethod
    def _tool_message(tool_call: dict[str, Any], routed: dict[str, Any]) -> ToolMessage:
        name = str(tool_call.get("name") or "claimsieve_routed_tool")
        call_id = str(tool_call.get("id") or "")
        payload = {
            **routed,
            "message": (
                "Consequential action routed to ClaimSieve. No external action "
                "was executed by the Deep Agents runtime."
            ),
        }
        return ToolMessage(
            content=json.dumps(payload, sort_keys=True, separators=(",", ":")),
            tool_call_id=call_id,
            name=name,
            status="success",
        )

    def wrap_tool_call(
        self,
        request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], ToolMessage | Command],
    ) -> ToolMessage | Command:
        tool_name = request.tool_call["name"]
        if not self._adapter.is_consequential(tool_name):
            return handler(request)
        routed = self._adapter.route_tool_call(request.tool_call)
        return self._tool_message(request.tool_call, routed)

    async def awrap_tool_call(
        self,
        request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], Awaitable[ToolMessage | Command]],
    ) -> ToolMessage | Command:
        tool_name = request.tool_call["name"]
        if not self._adapter.is_consequential(tool_name):
            return await handler(request)
        routed = self._adapter.route_tool_call(request.tool_call)
        return self._tool_message(request.tool_call, routed)
