from __future__ import annotations

import unittest

from mainstreet_runtimes import (
    OpenHandsAdapterError,
    OpenHandsProposalAdapter,
    OpenHandsRuntimeContext,
)


class OpenHandsProposalAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.routed: list[dict] = []
        self.context = OpenHandsRuntimeContext(
            trace_id="trace-openhands-001",
            campaign_id="campaign-openhands-001",
            session_id="session-openhands-001",
            work_item_id="work-openhands-001",
            requested_at_seq=30,
        )

        def route(intent: dict) -> dict:
            self.routed.append(intent)
            return {
                "status": "CLAIMSIEVE_INTAKE_ACCEPTED",
                "intent_digest": "fixture-openhands-intent-digest",
            }

        self.adapter = OpenHandsProposalAdapter(self.context, route)

    def test_mcp_action_is_canonicalized_without_execution_or_reasoning_leakage(self) -> None:
        result = self.adapter.route_event(
            {
                "tool_call_id": "call-oh-001",
                "tool_name": "create_github_issue",
                "security_risk": "HIGH",
                "thought": [{"type": "text", "text": "untrusted reasoning"}],
                "reasoning_content": "must not become authority",
                "action": {
                    "kind": "MCPToolAction",
                    "data": {
                        "repository": "example/claimsieve-mainstreet",
                        "title": "OpenHands boundary test",
                        "body": "Proposal only.",
                    },
                },
            }
        )

        self.assertTrue(result["routed_to_claimsieve"])
        self.assertFalse(result["external_action_executed"])
        self.assertEqual(result["runtime"], "openhands")
        self.assertEqual(len(self.routed), 1)
        intent = self.routed[0]
        self.assertEqual(intent["schema_version"], "mainstreet.consequential_tool_intent.v1")
        self.assertEqual(intent["tool_call_id"], "call-oh-001")
        self.assertEqual(intent["runtime"], "openhands")
        self.assertEqual(
            intent["arguments"],
            {
                "repository": "example/claimsieve-mainstreet",
                "title": "OpenHands boundary test",
                "body": "Proposal only.",
            },
        )
        self.assertNotIn("thought", intent)
        self.assertNotIn("reasoning_content", intent)
        self.assertNotIn("security_risk", intent)

    def test_openhands_low_risk_label_never_authorizes_execution(self) -> None:
        adapter = OpenHandsProposalAdapter(
            self.context,
            lambda intent: {
                "status": "UNTRUSTED_ROUTE_RESPONSE",
                "external_action_executed": True,
            },
        )
        result = adapter.route_event(
            {
                "tool_call_id": "call-oh-002",
                "tool_name": "terminal",
                "security_risk": "LOW",
                "action": {
                    "kind": "ExecuteBashAction",
                    "command": "printf test",
                    "is_input": False,
                    "timeout": 5,
                    "reset": False,
                },
            }
        )
        self.assertFalse(result["external_action_executed"])
        self.assertTrue(result["routed_to_claimsieve"])

    def test_mcp_arguments_are_copied_before_routing(self) -> None:
        data = {"destination": "customer-001", "amount": 100}
        event = {
            "tool_call_id": "call-oh-003",
            "tool_name": "issue_refund",
            "action": {"kind": "MCPToolAction", "data": data},
        }
        intent = self.adapter.build_intent(event)
        data["amount"] = 9000
        event["action"]["data"]["destination"] = "attacker"
        self.assertEqual(intent.arguments["amount"], 100)
        self.assertEqual(intent.arguments["destination"], "customer-001")

        materialized = intent.to_dict()
        materialized["arguments"]["amount"] = 5000
        self.assertEqual(intent.arguments["amount"], 100)

    def test_file_view_is_consequential_because_read_access_can_disclose_data(self) -> None:
        event = {
            "tool_call_id": "call-oh-004",
            "tool_name": "file_editor",
            "action": {
                "kind": "FileEditorAction",
                "command": "view",
                "path": "/workspace/README.md",
                "file_text": None,
                "old_str": None,
                "new_str": None,
                "insert_line": None,
                "view_range": None,
            },
        }
        self.assertTrue(self.adapter.is_consequential_event(event))
        result = self.adapter.route_event(event)
        self.assertTrue(result["routed_to_claimsieve"])
        self.assertFalse(result["external_action_executed"])

    def test_file_create_is_consequential(self) -> None:
        result = self.adapter.route_event(
            {
                "tool_call_id": "call-oh-005",
                "tool_name": "file_editor",
                "action": {
                    "kind": "FileEditorAction",
                    "command": "create",
                    "path": "/workspace/new.txt",
                    "file_text": "content",
                    "old_str": None,
                    "new_str": None,
                    "insert_line": None,
                    "view_range": None,
                },
            }
        )
        self.assertTrue(result["routed_to_claimsieve"])
        self.assertFalse(result["external_action_executed"])
        self.assertEqual(self.routed[0]["arguments"]["path"], "/workspace/new.txt")

    def test_execute_bash_is_always_consequential(self) -> None:
        event = {
            "tool_call_id": "call-oh-006",
            "tool_name": "terminal",
            "action": {
                "kind": "ExecuteBashAction",
                "command": "echo harmless-looking",
                "is_input": False,
                "timeout": None,
                "reset": False,
            },
        }
        self.assertTrue(self.adapter.is_consequential_event(event))

    def test_switching_model_profile_is_consequential(self) -> None:
        event = {
            "tool_call_id": "call-oh-007",
            "tool_name": "switch_llm",
            "action": {
                "kind": "SwitchLLMAction",
                "profile_name": "another-profile",
                "reason": "test",
            },
        }
        self.assertTrue(self.adapter.is_consequential_event(event))

    def test_glob_file_discovery_is_consequential(self) -> None:
        event = {
            "tool_call_id": "call-oh-008",
            "tool_name": "glob",
            "action": {
                "kind": "GlobAction",
                "pattern": "**/*.env",
                "path": "/workspace",
            },
        }
        self.assertTrue(self.adapter.is_consequential_event(event))

    def test_internal_think_action_is_not_routable_as_consequential(self) -> None:
        event = {
            "tool_call_id": "call-oh-009",
            "tool_name": "think",
            "action": {"kind": "ThinkAction", "thought": "plan only"},
        }
        self.assertFalse(self.adapter.is_consequential_event(event))
        with self.assertRaisesRegex(OpenHandsAdapterError, "not configured as consequential"):
            self.adapter.route_event(event)
        self.assertEqual(self.routed, [])

    def test_unknown_action_kind_fails_closed(self) -> None:
        with self.assertRaisesRegex(OpenHandsAdapterError, "unreviewed OpenHands action kind"):
            self.adapter.is_consequential_event(
                {
                    "tool_call_id": "call-oh-010",
                    "tool_name": "future_tool",
                    "action": {"kind": "FutureSideEffectAction", "value": "x"},
                }
            )

    def test_malformed_mcp_data_is_rejected(self) -> None:
        with self.assertRaisesRegex(OpenHandsAdapterError, "MCPToolAction.data must be a mapping"):
            self.adapter.build_intent(
                {
                    "tool_call_id": "call-oh-011",
                    "tool_name": "mcp_tool",
                    "action": {"kind": "MCPToolAction", "data": "not-a-mapping"},
                }
            )

    def test_missing_tool_call_id_is_rejected(self) -> None:
        with self.assertRaisesRegex(OpenHandsAdapterError, "tool_call_id"):
            self.adapter.build_intent(
                {
                    "tool_name": "terminal",
                    "action": {
                        "kind": "ExecuteBashAction",
                        "command": "echo test",
                        "is_input": False,
                        "timeout": None,
                        "reset": False,
                    },
                }
            )

    def test_invalid_runtime_sequence_is_rejected(self) -> None:
        with self.assertRaisesRegex(OpenHandsAdapterError, "non-negative integer"):
            OpenHandsProposalAdapter(
                OpenHandsRuntimeContext(
                    trace_id="trace",
                    campaign_id="campaign",
                    session_id="session",
                    work_item_id="work",
                    requested_at_seq=-1,
                ),
                lambda intent: intent,
            )


if __name__ == "__main__":
    unittest.main()
