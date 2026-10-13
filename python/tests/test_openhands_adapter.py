from __future__ import annotations

import unittest

from mainstreet_runtimes import (
    PINNED_OPENHANDS_COMMIT,
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
                "external_action_executed": False,
            }

        self.adapter = OpenHandsProposalAdapter(self.context, route)

    def mcp_event(self) -> dict:
        return {
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

    def test_mcp_intent_binds_runtime_revision_and_action_kind(self) -> None:
        result = self.adapter.route_event(self.mcp_event())
        self.assertTrue(result["routed_to_claimsieve"])
        self.assertFalse(result["external_action_executed"])
        self.assertEqual(result["runtime"], "openhands")
        self.assertEqual(result["runtime_version"], PINNED_OPENHANDS_COMMIT)
        self.assertEqual(result["action_kind"], "MCPToolAction")

        intent = self.routed[0]
        self.assertEqual(intent["schema_version"], "mainstreet.consequential_tool_intent.v2")
        self.assertEqual(intent["runtime"], "openhands")
        self.assertEqual(intent["runtime_version"], PINNED_OPENHANDS_COMMIT)
        self.assertEqual(intent["action_kind"], "MCPToolAction")
        self.assertEqual(intent["tool_call_id"], "call-oh-001")
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

    def test_low_risk_label_cannot_bypass_proposal_only_route_contract(self) -> None:
        adapter = OpenHandsProposalAdapter(
            self.context,
            lambda intent: {
                "status": "UNTRUSTED_ROUTE_RESPONSE",
                "external_action_executed": True,
            },
        )
        event = {
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
        with self.assertRaisesRegex(OpenHandsAdapterError, "proposal-only receipt"):
            adapter.route_event(event)

    def test_route_receipt_must_explicitly_state_no_external_execution(self) -> None:
        adapter = OpenHandsProposalAdapter(
            self.context,
            lambda intent: {"status": "AMBIGUOUS"},
        )
        event = {
            "tool_call_id": "call-oh-003",
            "tool_name": "terminal",
            "action": {
                "kind": "TerminalAction",
                "command": "echo test",
                "is_input": False,
                "timeout": None,
                "reset": False,
            },
        }
        with self.assertRaisesRegex(OpenHandsAdapterError, "proposal-only receipt"):
            adapter.route_event(event)

    def test_arguments_are_deep_copied_before_authority_routing(self) -> None:
        data = {"destination": "customer-001", "amount": 100}
        event = {
            "tool_call_id": "call-oh-004",
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

    def test_confidentiality_and_user_output_capabilities_are_consequential(self) -> None:
        events = (
            {
                "tool_call_id": "call-oh-005",
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
            },
            {
                "tool_call_id": "call-oh-006",
                "tool_name": "glob",
                "action": {
                    "kind": "GlobAction",
                    "pattern": "**/*.env",
                    "path": "/workspace",
                },
            },
            {
                "tool_call_id": "call-oh-007",
                "tool_name": "finish",
                "action": {
                    "kind": "FinishAction",
                    "message": "Customer-facing answer",
                },
            },
        )
        for event in events:
            with self.subTest(kind=event["action"]["kind"]):
                self.assertTrue(self.adapter.is_consequential_event(event))

    def test_runtime_graph_and_generated_client_actions_are_consequential(self) -> None:
        events = (
            {
                "tool_call_id": "call-oh-008",
                "tool_name": "switch_llm",
                "action": {
                    "kind": "SwitchLLMAction",
                    "profile_name": "another-profile",
                    "reason": "test",
                },
            },
            {
                "tool_call_id": "call-oh-009",
                "tool_name": "canvas_ui_control",
                "action": {
                    "kind": "ClientAction_canvas_ui_control",
                    "command": "open_tab",
                    "tab": "preview",
                },
            },
            {
                "tool_call_id": "call-oh-010",
                "tool_name": "launch_child_conversation",
                "action": {
                    "kind": "ClientAction_launch_child_conversation",
                    "target": "local",
                    "task": "inspect boundary",
                },
            },
        )
        for event in events:
            with self.subTest(kind=event["action"]["kind"]):
                self.assertTrue(self.adapter.is_consequential_event(event))

    def test_internal_think_action_is_not_routable(self) -> None:
        event = {
            "tool_call_id": "call-oh-011",
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
                    "tool_call_id": "call-oh-012",
                    "tool_name": "future_tool",
                    "action": {"kind": "FutureSideEffectAction", "value": "x"},
                }
            )

    def test_malformed_mcp_data_and_missing_identity_are_rejected(self) -> None:
        with self.assertRaisesRegex(OpenHandsAdapterError, "MCPToolAction.data must be a mapping"):
            self.adapter.build_intent(
                {
                    "tool_call_id": "call-oh-013",
                    "tool_name": "mcp_tool",
                    "action": {"kind": "MCPToolAction", "data": "not-a-mapping"},
                }
            )
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
