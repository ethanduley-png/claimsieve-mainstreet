from __future__ import annotations

import unittest

from mainstreet_runtimes import (
    ClaimSieveRuntimeContext,
    DeepAgentsAdapterError,
    DeepAgentsProposalAdapter,
)


class DeepAgentsProposalAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.routed: list[dict] = []
        self.context = ClaimSieveRuntimeContext(
            trace_id="trace-deepagents-001",
            campaign_id="campaign-deepagents-001",
            session_id="session-deepagents-001",
            work_item_id="work-deepagents-001",
            requested_at_seq=20,
        )

        def route(intent: dict) -> dict:
            self.routed.append(intent)
            return {
                "status": "CLAIMSIEVE_INTAKE_ACCEPTED",
                "intent_digest": "fixture-intent-digest",
            }

        self.adapter = DeepAgentsProposalAdapter(self.context, route)

    def test_consequential_call_is_canonicalized_and_routed_without_execution(self) -> None:
        result = self.adapter.route_tool_call(
            {
                "id": "call-001",
                "name": "create_github_issue",
                "args": {
                    "repository": "example/claimsieve-mainstreet",
                    "title": "Review Deep Agents adapter",
                    "body": "No provider execution from the proposal runtime.",
                },
            }
        )
        self.assertTrue(result["routed_to_claimsieve"])
        self.assertFalse(result["external_action_executed"])
        self.assertEqual(result["runtime"], "deepagents")
        self.assertEqual(len(self.routed), 1)
        intent = self.routed[0]
        self.assertEqual(intent["schema_version"], "mainstreet.consequential_tool_intent.v1")
        self.assertEqual(intent["tool_call_id"], "call-001")
        self.assertEqual(intent["context"]["work_item_id"], "work-deepagents-001")

    def test_arguments_are_copied_before_routing(self) -> None:
        args = {"amount": 100, "customer_id": "customer-001"}
        intent = self.adapter.build_intent(
            {"id": "call-002", "name": "issue_refund", "args": args}
        )
        args["amount"] = 9000
        self.assertEqual(intent.arguments["amount"], 100)
        materialized = intent.to_dict()
        materialized["arguments"]["amount"] = 5000
        self.assertEqual(intent.arguments["amount"], 100)

    def test_non_consequential_tool_cannot_be_routed_through_adapter(self) -> None:
        with self.assertRaisesRegex(DeepAgentsAdapterError, "not configured as consequential"):
            self.adapter.route_tool_call(
                {"id": "call-003", "name": "read_file", "args": {"path": "/notes.txt"}}
            )
        self.assertEqual(self.routed, [])

    def test_missing_tool_call_id_is_rejected(self) -> None:
        with self.assertRaisesRegex(DeepAgentsAdapterError, "tool call id"):
            self.adapter.build_intent({"name": "send_email", "args": {}})

    def test_invalid_runtime_sequence_is_rejected(self) -> None:
        with self.assertRaisesRegex(DeepAgentsAdapterError, "non-negative integer"):
            DeepAgentsProposalAdapter(
                ClaimSieveRuntimeContext(
                    trace_id="trace",
                    campaign_id="campaign",
                    session_id="session",
                    work_item_id="work",
                    requested_at_seq=-1,
                ),
                lambda intent: intent,
            )

    def test_custom_consequential_tool_set_is_exact(self) -> None:
        adapter = DeepAgentsProposalAdapter(
            self.context,
            lambda intent: {"status": "ACCEPTED"},
            consequential_tools={"custom_external_write"},
        )
        self.assertTrue(adapter.is_consequential("custom_external_write"))
        self.assertFalse(adapter.is_consequential("issue_refund"))


if __name__ == "__main__":
    unittest.main()
