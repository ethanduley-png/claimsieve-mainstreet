from __future__ import annotations

import copy
from typing import Any, Callable, Mapping

from .deepagents_adapter import ClaimSieveRuntimeContext, ConsequentialToolIntent


class OpenWorkerAdapterError(ValueError):
    """Raised when an untrusted OpenWorker boundary call cannot be canonicalized."""


RouteIntent = Callable[[dict[str, Any]], Mapping[str, Any]]


class OpenWorkerProposalAdapter:
    """Translate normalized OpenWorker calls into ClaimSieve-bound intents.

    This adapter intentionally consumes a small MainStreet-owned boundary shape
    instead of depending on OpenWorker's internal tool-call classes. Upstream
    OpenWorker code may change without becoming part of the ClaimSieve trust
    boundary.

    The adapter never executes tools and never issues ClaimSieve permits.
    """

    BOUNDARY_SCHEMA = "mainstreet.openworker_tool_call.v1"
    INTENT_SCHEMA = "mainstreet.consequential_tool_intent.v1"
    RUNTIME = "openworker"
    REQUIRED_FIELDS = frozenset({"schema_version", "id", "name", "arguments"})
    DEFAULT_CONSEQUENTIAL_TOOLS = frozenset(
        {
            "create_github_issue",
            "send_email",
            "issue_refund",
            "update_crm_record",
        }
    )

    def __init__(
        self,
        context: ClaimSieveRuntimeContext,
        route_intent: RouteIntent,
        consequential_tools: set[str] | frozenset[str] | None = None,
    ) -> None:
        context.validate()
        if not callable(route_intent):
            raise OpenWorkerAdapterError("route_intent must be callable")
        selected = (
            self.DEFAULT_CONSEQUENTIAL_TOOLS
            if consequential_tools is None
            else frozenset(consequential_tools)
        )
        if not selected:
            raise OpenWorkerAdapterError("at least one consequential tool is required")
        for name in selected:
            if not isinstance(name, str) or not name or len(name) > 128:
                raise OpenWorkerAdapterError(
                    "consequential tool names must be non-empty strings of at most 128 characters"
                )
        self._context = context
        self._route_intent = route_intent
        self._consequential_tools = frozenset(selected)

    @property
    def consequential_tools(self) -> frozenset[str]:
        return self._consequential_tools

    def is_consequential(self, tool_name: str) -> bool:
        return tool_name in self._consequential_tools

    def build_intent(self, tool_call: Mapping[str, Any]) -> ConsequentialToolIntent:
        if not isinstance(tool_call, Mapping):
            raise OpenWorkerAdapterError("tool_call must be a mapping")
        if frozenset(tool_call) != self.REQUIRED_FIELDS:
            raise OpenWorkerAdapterError("OpenWorker boundary fields do not match the required schema")
        if tool_call.get("schema_version") != self.BOUNDARY_SCHEMA:
            raise OpenWorkerAdapterError("unsupported OpenWorker boundary schema")

        tool_name = tool_call.get("name")
        tool_call_id = tool_call.get("id")
        arguments = tool_call.get("arguments")
        if not isinstance(tool_name, str) or not tool_name or len(tool_name) > 128:
            raise OpenWorkerAdapterError("tool call name must be a non-empty string of at most 128 characters")
        if tool_name not in self._consequential_tools:
            raise OpenWorkerAdapterError(f"tool is not configured as consequential: {tool_name}")
        if not isinstance(tool_call_id, str) or not tool_call_id or len(tool_call_id) > 110:
            raise OpenWorkerAdapterError("tool call id must be a non-empty string of at most 110 characters")
        if not isinstance(arguments, Mapping):
            raise OpenWorkerAdapterError("tool call arguments must be a mapping")

        return ConsequentialToolIntent(
            schema_version=self.INTENT_SCHEMA,
            runtime=self.RUNTIME,
            tool_call_id=tool_call_id,
            tool_name=tool_name,
            arguments=copy.deepcopy(dict(arguments)),
            context=self._context,
        )

    def route_tool_call(self, tool_call: Mapping[str, Any]) -> dict[str, Any]:
        intent = self.build_intent(tool_call)
        routed = self._route_intent(intent.to_dict())
        if not isinstance(routed, Mapping):
            raise OpenWorkerAdapterError("route_intent must return a mapping")
        return {
            "schema_version": "mainstreet.claimsieve_route_result.v1",
            "runtime": self.RUNTIME,
            "tool_call_id": intent.tool_call_id,
            "tool_name": intent.tool_name,
            "routed_to_claimsieve": True,
            "external_action_executed": False,
            "claimsieve": copy.deepcopy(dict(routed)),
        }
