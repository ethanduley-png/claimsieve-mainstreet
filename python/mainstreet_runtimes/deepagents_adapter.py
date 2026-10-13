from __future__ import annotations

import copy
from dataclasses import asdict, dataclass
from typing import Any, Callable, Mapping


class DeepAgentsAdapterError(ValueError):
    """Raised when an untrusted Deep Agents tool call cannot be canonicalized."""


@dataclass(frozen=True)
class ClaimSieveRuntimeContext:
    """Caller-supplied identifiers bound to one proposal-side agent session.

    This object contains correlation metadata only. It is not authorization and
    must never be treated as a permit, approval, or provider credential.
    """

    trace_id: str
    campaign_id: str
    session_id: str
    work_item_id: str
    requested_at_seq: int

    def validate(self) -> None:
        for name in ("trace_id", "campaign_id", "session_id", "work_item_id"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value or len(value) > 256:
                raise DeepAgentsAdapterError(
                    f"{name} must be a non-empty string of at most 256 characters"
                )
        if (
            isinstance(self.requested_at_seq, bool)
            or not isinstance(self.requested_at_seq, int)
            or self.requested_at_seq < 0
        ):
            raise DeepAgentsAdapterError("requested_at_seq must be a non-negative integer")


@dataclass(frozen=True)
class ConsequentialToolIntent:
    """Canonical proposal-side envelope emitted instead of executing a tool."""

    schema_version: str
    runtime: str
    tool_call_id: str
    tool_name: str
    arguments: dict[str, Any]
    context: ClaimSieveRuntimeContext

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "runtime": self.runtime,
            "tool_call_id": self.tool_call_id,
            "tool_name": self.tool_name,
            "arguments": copy.deepcopy(self.arguments),
            "context": asdict(self.context),
        }


RouteIntent = Callable[[dict[str, Any]], Mapping[str, Any]]


class DeepAgentsProposalAdapter:
    """Translate consequential Deep Agents calls into ClaimSieve-bound intents.

    The adapter does not execute tools and does not issue ClaimSieve permits. A
    separate intake/authority path must validate the returned intent and decide
    whether any downstream execution is authorized.
    """

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
            raise DeepAgentsAdapterError("route_intent must be callable")
        selected = (
            self.DEFAULT_CONSEQUENTIAL_TOOLS
            if consequential_tools is None
            else frozenset(consequential_tools)
        )
        if not selected:
            raise DeepAgentsAdapterError("at least one consequential tool is required")
        for name in selected:
            if not isinstance(name, str) or not name or len(name) > 128:
                raise DeepAgentsAdapterError(
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
            raise DeepAgentsAdapterError("tool_call must be a mapping")
        tool_name = tool_call.get("name")
        tool_call_id = tool_call.get("id")
        arguments = tool_call.get("args", {})
        if not isinstance(tool_name, str) or not tool_name:
            raise DeepAgentsAdapterError("tool call name must be a non-empty string")
        if tool_name not in self._consequential_tools:
            raise DeepAgentsAdapterError(f"tool is not configured as consequential: {tool_name}")
        if not isinstance(tool_call_id, str) or not tool_call_id:
            raise DeepAgentsAdapterError("tool call id must be a non-empty string")
        if not isinstance(arguments, Mapping):
            raise DeepAgentsAdapterError("tool call args must be a mapping")
        return ConsequentialToolIntent(
            schema_version="mainstreet.consequential_tool_intent.v1",
            runtime="deepagents",
            tool_call_id=tool_call_id,
            tool_name=tool_name,
            arguments=copy.deepcopy(dict(arguments)),
            context=self._context,
        )

    def route_tool_call(self, tool_call: Mapping[str, Any]) -> dict[str, Any]:
        intent = self.build_intent(tool_call)
        routed = self._route_intent(intent.to_dict())
        if not isinstance(routed, Mapping):
            raise DeepAgentsAdapterError("route_intent must return a mapping")
        route_result = copy.deepcopy(dict(routed))
        return {
            "schema_version": "mainstreet.claimsieve_route_result.v1",
            "runtime": "deepagents",
            "tool_call_id": intent.tool_call_id,
            "tool_name": intent.tool_name,
            "routed_to_claimsieve": True,
            "external_action_executed": False,
            "claimsieve": route_result,
        }
