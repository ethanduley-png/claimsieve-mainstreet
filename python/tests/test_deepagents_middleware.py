from __future__ import annotations

import inspect
import json
import unittest
from types import SimpleNamespace

from mainstreet_runtimes import ClaimSieveRuntimeContext, DeepAgentsProposalAdapter

try:
    from deepagents import create_deep_agent
    from langchain_core.messages import ToolMessage

    from mainstreet_runtimes.deepagents_middleware import ClaimSieveDeepAgentsMiddleware

    DEEPAGENTS_AVAILABLE = True
except ImportError:
    create_deep_agent = None
    ToolMessage = None
    ClaimSieveDeepAgentsMiddleware = None
    DEEPAGENTS_AVAILABLE = False


@unittest.skipUnless(DEEPAGENTS_AVAILABLE, "deepagents optional dependency is not installed")
class ClaimSieveDeepAgentsMiddlewareTests(unittest.TestCase):
    def setUp(self) -> None:
        self.routed: list[dict] = []
        context = ClaimSieveRuntimeContext(
            trace_id="trace-middleware-001",
            campaign_id="campaign-middleware-001",
            session_id="session-middleware-001",
            work_item_id="work-middleware-001",
            requested_at_seq=30,
        )

        def route(intent: dict) -> dict:
            self.routed.append(intent)
            return {"status": "PERMIT_PENDING", "intent_digest": "fixture-digest"}

        self.adapter = DeepAgentsProposalAdapter(context, route)
        self.middleware = ClaimSieveDeepAgentsMiddleware(self.adapter)

    def test_upstream_create_deep_agent_exposes_middleware_extension_point(self) -> None:
        self.assertIn("middleware", inspect.signature(create_deep_agent).parameters)

    def test_consequential_tool_does_not_reach_underlying_handler(self) -> None:
        request = SimpleNamespace(
            tool_call={
                "id": "call-refund-001",
                "name": "issue_refund",
                "args": {"customer_id": "customer-001", "amount": 100},
            }
        )
        handler_called = False

        def handler(_request):
            nonlocal handler_called
            handler_called = True
            return ToolMessage(
                content="provider executed",
                tool_call_id="call-refund-001",
                name="issue_refund",
                status="success",
            )

        result = self.middleware.wrap_tool_call(request, handler)
        self.assertFalse(handler_called)
        self.assertIsInstance(result, ToolMessage)
        payload = json.loads(result.content)
        self.assertTrue(payload["routed_to_claimsieve"])
        self.assertFalse(payload["external_action_executed"])
        self.assertEqual(payload["claimsieve"]["status"], "PERMIT_PENDING")
        self.assertEqual(len(self.routed), 1)

    def test_non_consequential_tool_reaches_underlying_handler(self) -> None:
        request = SimpleNamespace(
            tool_call={"id": "call-read-001", "name": "read_file", "args": {"path": "/notes.txt"}}
        )
        handler_called = False

        def handler(_request):
            nonlocal handler_called
            handler_called = True
            return ToolMessage(
                content="notes",
                tool_call_id="call-read-001",
                name="read_file",
                status="success",
            )

        result = self.middleware.wrap_tool_call(request, handler)
        self.assertTrue(handler_called)
        self.assertEqual(result.content, "notes")
        self.assertEqual(self.routed, [])


if __name__ == "__main__":
    unittest.main()
