from __future__ import annotations

import copy
from dataclasses import asdict, dataclass
from typing import Any, Callable, Mapping


class OpenHandsAdapterError(ValueError):
    """Raised when an untrusted OpenHands action cannot be canonicalized."""


@dataclass(frozen=True)
class OpenHandsRuntimeContext:
    """Correlation metadata for one proposal-side OpenHands session.

    These fields are not authorization. They must never be treated as a permit,
    approval, provider credential, or proof that an action is safe.
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
                raise OpenHandsAdapterError(
                    f"{name} must be a non-empty string of at most 256 characters"
                )
        if (
            isinstance(self.requested_at_seq, bool)
            or not isinstance(self.requested_at_seq, int)
            or self.requested_at_seq < 0
        ):
            raise OpenHandsAdapterError("requested_at_seq must be a non-negative integer")


@dataclass(frozen=True)
class OpenHandsConsequentialIntent:
    """Canonical proposal envelope emitted instead of executing an OpenHands action."""

    schema_version: str
    runtime: str
    tool_call_id: str
    tool_name: str
    arguments: dict[str, Any]
    context: OpenHandsRuntimeContext

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


class OpenHandsProposalAdapter:
    """Route reviewed OpenHands capabilities to the ClaimSieve proposal boundary.

    The adapter is intentionally proposal-only. It never executes OpenHands
    actions, issues ClaimSieve permits, owns provider credentials, or interprets
    an OpenHands security-risk label as authorization.

    The input contract follows OpenHands ActionEvent: ``tool_name``,
    ``tool_call_id``, and an ``action`` mapping with a ``kind`` discriminator.
    Reasoning/thought fields are deliberately ignored and are not copied into the
    ClaimSieve intent.

    This first baseline is deliberately conservative. Capabilities that can
    execute code, access files or browser state, invoke skills/tools, change the
    model/runtime graph, spawn work, or emit user-visible output are treated as
    consequential. Read access is included because confidentiality loss is a
    consequential effect even when no external write occurs. Unknown action
    kinds fail closed.
    """

    CONSEQUENTIAL_ACTION_KINDS = frozenset(
        {
            "ExecuteBashAction",
            "TerminalAction",
            "MCPToolAction",
            "FileEditorAction",
            "StrReplaceEditorAction",
            "PlanningFileEditorAction",
            "GlobAction",
            "GrepAction",
            "BrowserNavigateAction",
            "BrowserClickAction",
            "BrowserTypeAction",
            "BrowserGetStateAction",
            "BrowserGetContentAction",
            "BrowserScrollAction",
            "BrowserGoBackAction",
            "BrowserListTabsAction",
            "BrowserSwitchTabAction",
            "BrowserCloseTabAction",
            "InvokeSkillAction",
            "TaskAction",
            "SwitchLLMAction",
            "CanvasUIAction",
            "ClientAction_canvas_ui_control",
            "LaunchChildConversationAction",
            "ClientAction_launch_child_conversation",
            "FinishAction",
        }
    )

    NON_CONSEQUENTIAL_ACTION_KINDS = frozenset(
        {
            "ThinkAction",
            "TaskTrackerAction",
        }
    )

    def __init__(
        self,
        context: OpenHandsRuntimeContext,
        route_intent: RouteIntent,
        extra_consequential_action_kinds: set[str] | frozenset[str] | None = None,
    ) -> None:
        context.validate()
        if not callable(route_intent):
            raise OpenHandsAdapterError("route_intent must be callable")
        extra = frozenset(extra_consequential_action_kinds or ())
        for kind in extra:
            if not isinstance(kind, str) or not kind or len(kind) > 128:
                raise OpenHandsAdapterError(
                    "extra consequential action kinds must be non-empty strings of at most 128 characters"
                )
        self._context = context
        self._route_intent = route_intent
        self._extra_consequential_action_kinds = extra

    @staticmethod
    def _mapping(value: Any, name: str) -> Mapping[str, Any]:
        if not isinstance(value, Mapping):
            raise OpenHandsAdapterError(f"{name} must be a mapping")
        return value

    @staticmethod
    def _nonempty_string(value: Any, name: str, maximum: int = 256) -> str:
        if not isinstance(value, str) or not value or len(value) > maximum:
            raise OpenHandsAdapterError(
                f"{name} must be a non-empty string of at most {maximum} characters"
            )
        return value

    def is_consequential_event(self, event: Mapping[str, Any]) -> bool:
        event_map = self._mapping(event, "event")
        action = self._mapping(event_map.get("action"), "action")
        kind = self._nonempty_string(action.get("kind"), "action.kind", 128)

        if kind in self.CONSEQUENTIAL_ACTION_KINDS:
            return True
        if kind in self._extra_consequential_action_kinds:
            return True
        if kind in self.NON_CONSEQUENTIAL_ACTION_KINDS:
            return False

        # Upstream may add action kinds without ClaimSieve having reviewed their
        # authority, confidentiality, or side-effect semantics. Never silently
        # classify such a capability as safe.
        raise OpenHandsAdapterError(f"unreviewed OpenHands action kind: {kind}")

    def build_intent(self, event: Mapping[str, Any]) -> OpenHandsConsequentialIntent:
        event_map = self._mapping(event, "event")
        if not self.is_consequential_event(event_map):
            action = self._mapping(event_map.get("action"), "action")
            raise OpenHandsAdapterError(
                f"OpenHands action is not configured as consequential: {action.get('kind')}"
            )

        tool_name = self._nonempty_string(event_map.get("tool_name"), "tool_name", 128)
        tool_call_id = self._nonempty_string(
            event_map.get("tool_call_id"), "tool_call_id", 256
        )
        action = self._mapping(event_map.get("action"), "action")
        kind = self._nonempty_string(action.get("kind"), "action.kind", 128)

        if kind == "MCPToolAction":
            data = self._mapping(action.get("data"), "MCPToolAction.data")
            arguments = copy.deepcopy(dict(data))
        else:
            arguments = copy.deepcopy(
                {key: value for key, value in action.items() if key != "kind"}
            )

        return OpenHandsConsequentialIntent(
            schema_version="mainstreet.consequential_tool_intent.v1",
            runtime="openhands",
            tool_call_id=tool_call_id,
            tool_name=tool_name,
            arguments=arguments,
            context=self._context,
        )

    def route_event(self, event: Mapping[str, Any]) -> dict[str, Any]:
        intent = self.build_intent(event)
        routed = self._route_intent(intent.to_dict())
        if not isinstance(routed, Mapping):
            raise OpenHandsAdapterError("route_intent must return a mapping")
        route_result = copy.deepcopy(dict(routed))
        if route_result.get("external_action_executed") is not False:
            raise OpenHandsAdapterError(
                "route_intent must return an explicit proposal-only receipt with external_action_executed false"
            )
        return {
            "schema_version": "mainstreet.claimsieve_route_result.v1",
            "runtime": "openhands",
            "tool_call_id": intent.tool_call_id,
            "tool_name": intent.tool_name,
            "routed_to_claimsieve": True,
            "external_action_executed": False,
            "claimsieve": route_result,
        }
