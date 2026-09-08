from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from founder_os import FounderOSReferenceWorkflow
from mainstreet_runtimes import (
    PINNED_OPENHANDS_COMMIT,
    AuthenticatedRuntimeBinding,
    OpenHandsAuthenticatedRoute,
    OpenHandsFounderIntake,
    OpenHandsProposalAdapter,
    OpenHandsRuntimeContext,
    OpenHandsTransportError,
)


class OpenHandsAuthenticatedTransportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.repository = "example/claimsieve-mainstreet"
        self.workflow = FounderOSReferenceWorkflow(
            self.root,
            allowed_repositories={self.repository},
            provider_mode="success",
            runtime_name="openhands",
            runtime_version=PINNED_OPENHANDS_COMMIT,
        )
        self.intake = OpenHandsFounderIntake(self.workflow)
        self.binding = AuthenticatedRuntimeBinding.from_mapping(
            self.workflow.runtime_profile.binding()
        )
        self.transport = OpenHandsAuthenticatedRoute(
            self.intake,
            self.binding,
        )
        self.adapter = OpenHandsProposalAdapter(
            OpenHandsRuntimeContext(
                trace_id="trace-openhands-transport",
                campaign_id="campaign-openhands-transport",
                session_id="session-openhands-transport",
                work_item_id="work-openhands-transport",
                requested_at_seq=70,
            ),
            self.transport.route_intent,
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def event(self, call_id: str = "call-transport-001") -> dict:
        return {
            "tool_call_id": call_id,
            "tool_name": "create_github_issue",
            "action": {
                "kind": "MCPToolAction",
                "data": {
                    "repository": self.repository,
                    "title": "Authenticated OpenHands route",
                    "body": "Runtime identity is supplied outside the proposal payload.",
                },
            },
        }

    def test_bound_transport_routes_to_permit_without_execution(self) -> None:
        routed = self.adapter.route_event(self.event())
        self.assertFalse(routed["external_action_executed"])
        self.assertEqual(
            routed["claimsieve"]["runtime_principal"],
            self.binding.principal,
        )
        self.assertEqual(
            self.transport.authenticated_binding,
            self.workflow.runtime_profile.binding(),
        )
        self.assertEqual(len(self.workflow.ledger_records()["execution"]), 0)

    def test_wrong_authenticated_principal_cannot_create_route(self) -> None:
        raw = self.workflow.runtime_profile.binding()
        raw["principal"] = "spiffe://mainstreet.local/tenant-founder/agent/attacker"
        forged = AuthenticatedRuntimeBinding.from_mapping(raw)
        with self.assertRaisesRegex(OpenHandsTransportError, "does not match"):
            OpenHandsAuthenticatedRoute(self.intake, forged)

    def test_wrong_authenticated_manifest_cannot_create_route(self) -> None:
        raw = self.workflow.runtime_profile.binding()
        raw["runtime_manifest_digest"] = "sha256:" + ("0" * 64)
        forged = AuthenticatedRuntimeBinding.from_mapping(raw)
        with self.assertRaisesRegex(OpenHandsTransportError, "does not match"):
            OpenHandsAuthenticatedRoute(self.intake, forged)

    def test_payload_cannot_replace_out_of_band_authenticated_binding(self) -> None:
        intent = self.adapter.build_intent(self.event("call-transport-002")).to_dict()
        intent["runtime"] = "openclaw"
        intent["runtime_version"] = "attacker-version"
        intent["action_kind"] = "ExecuteBashAction"

        before = self.transport.authenticated_binding
        with self.assertRaises(ValueError):
            self.transport.route_intent(intent)
        self.assertEqual(self.transport.authenticated_binding, before)

    def test_authenticated_binding_schema_is_exact(self) -> None:
        raw = self.workflow.runtime_profile.binding()
        raw["extra"] = "not-allowed"
        with self.assertRaisesRegex(OpenHandsTransportError, "required schema"):
            AuthenticatedRuntimeBinding.from_mapping(raw)


if __name__ == "__main__":
    unittest.main()
