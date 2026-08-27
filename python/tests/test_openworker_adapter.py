from __future__ import annotations

import unittest

from mainstreet_runtimes import ClaimSieveRuntimeContext
from mainstreet_runtimes.openworker_adapter import OpenWorkerAdapterError, OpenWorkerProposalAdapter


class OpenWorkerProposalAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.routed: list[dict] = []
        context = ClaimSieveRuntimeContext(
            trace_id="trace-openworker-001",
            campaign_id="campaign-openworker-001",
            session_id="session-openworker-001",
            work_item_id="work-openworker-001",
            requested_at_seq=50,
        )

        def route(intent: dict) -> dict:
            self.routed.append(intent)
            return {"status": "CLAIMSIEVE_INTAKE_ACCEPTED"}

        self.adapter = OpenWorkerProposalAdapter(context, route)

    @staticmethod
    def call() -> dict:
        return {
            "schema_version": "mainstreet.openworker_tool_call.v1",
            "id": "ow-call-001",
            "name": "create_github_issue",
            "arguments": {
                "repository": "example/claimsieve-mainstreet",
                "title": "Review OpenWorker adapter",
                "body": "OpenWorker remains on the proposal side of ClaimSieve.",
            },
        }

    def test_consequential_call_routes_without_execution(self) -> None:
        result = self.adapter.route_tool_call(self.call())
        self.assertTrue(result["routed_to_claimsieve"])
        self.assertFalse(result["external_action_executed"])
        self.assertEqual(result["runtime"], "openworker")
        self.assertEqual(len(self.routed), 1)
        self.assertEqual(self.routed[0]["runtime"], "openworker")
        self.assertEqual(
            self.routed[0]["schema_version"], "mainstreet.consequential_tool_intent.v1"
        )

    def test_unknown_boundary_field_is_rejected(self) -> None:
        call = self.call()
        call["approval"] = "allow"
        with self.assertRaisesRegex(OpenWorkerAdapterError, "boundary fields"):
            self.adapter.build_intent(call)
        self.assertEqual(self.routed, [])

    def test_wrong_boundary_version_is_rejected(self) -> None:
        call = self.call()
        call["schema_version"] = "mainstreet.openworker_tool_call.v2"
        with self.assertRaisesRegex(OpenWorkerAdapterError, "unsupported OpenWorker boundary schema"):
            self.adapter.build_intent(call)

    def test_arguments_are_defensively_copied(self) -> None:
        call = self.call()
        intent = self.adapter.build_intent(call)
        call["arguments"]["title"] = "mutated"
        self.assertEqual(intent.arguments["title"], "Review OpenWorker adapter")

    def test_non_consequential_tool_cannot_cross_boundary(self) -> None:
        call = self.call()
        call["name"] = "read_file"
        with self.assertRaisesRegex(OpenWorkerAdapterError, "not configured as consequential"):
            self.adapter.route_tool_call(call)
        self.assertEqual(self.routed, [])


if __name__ == "__main__":
    unittest.main()
