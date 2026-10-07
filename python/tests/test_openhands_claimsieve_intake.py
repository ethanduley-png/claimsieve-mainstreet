from __future__ import annotations

import tempfile
import threading
import unittest
from pathlib import Path

from claimsieve_ref.runtime import PermitError
from founder_os import FounderOSReferenceWorkflow, GitHubIssueRequest
from mainstreet_runtimes import (
    PINNED_OPENHANDS_COMMIT,
    OpenHandsFounderIntake,
    OpenHandsProposalAdapter,
    OpenHandsRuntimeContext,
)
from mainstreet_runtimes.claimsieve_intake import ClaimSieveIntakeError


class OpenHandsClaimSieveIntakeTests(unittest.TestCase):
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
        self.context = OpenHandsRuntimeContext(
            trace_id="trace-openhands-intake-001",
            campaign_id="campaign-openhands-intake-001",
            session_id="session-openhands-intake-001",
            work_item_id="work-openhands-intake-001",
            requested_at_seq=50,
        )
        self.adapter = OpenHandsProposalAdapter(self.context, self.intake.route_intent)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def mcp_event(self, call_id: str = "call-openhands-github-001") -> dict:
        return {
            "tool_call_id": call_id,
            "tool_name": "create_github_issue",
            "security_risk": "LOW",
            "thought": [{"type": "text", "text": "untrusted"}],
            "action": {
                "kind": "MCPToolAction",
                "data": {
                    "repository": self.repository,
                    "title": "Review OpenHands ClaimSieve intake",
                    "body": "Permit issuance must remain separate from provider execution.",
                },
            },
        }

    def direct_request(self, suffix: str) -> GitHubIssueRequest:
        return GitHubIssueRequest(
            proposal_id=f"proposal-{suffix}",
            trace_id=f"trace-{suffix}",
            campaign_id=f"campaign-{suffix}",
            session_id=f"session-{suffix}",
            work_item_id=f"work-{suffix}",
            repository=self.repository,
            title="Verify OpenHands runtime binding",
            body="The permit must remain bound to the pinned OpenHands runtime.",
            requested_at_seq=50,
        )

    def test_intent_reaches_existing_authority_and_stops_before_execution(self) -> None:
        routed = self.adapter.route_event(self.mcp_event())
        receipt = routed["claimsieve"]
        self.assertEqual(receipt["status"], "PERMIT_ISSUED_EXECUTION_PENDING")
        self.assertEqual(receipt["runtime_name"], "openhands")
        self.assertEqual(receipt["runtime_version"], PINNED_OPENHANDS_COMMIT)
        self.assertEqual(receipt["action_kind"], "MCPToolAction")
        self.assertEqual(receipt["tool_name"], "create_github_issue")
        self.assertEqual(
            receipt["runtime_principal"],
            "spiffe://mainstreet.local/tenant-founder/agent/openhands",
        )
        self.assertTrue(receipt["runtime_manifest_digest"].startswith("sha256:"))
        self.assertFalse(receipt["external_action_executed"])
        self.assertFalse(routed["external_action_executed"])
        self.assertEqual(len(self.workflow.ledger_records()["execution"]), 0)
        self.assertEqual(self.intake.pending_permits(), (receipt["permit_id"],))

    def test_existing_authority_binds_openhands_principal_manifest_and_deployment(self) -> None:
        prepared = self.workflow.prepare_issue(self.direct_request("identity"))
        profile = self.workflow.runtime_profile
        self.assertEqual(prepared.proposal["principal"], profile.principal)
        self.assertEqual(prepared.permit["principal"], profile.principal)
        self.assertEqual(prepared.policy["allowed_principals"], [profile.principal])
        self.assertEqual(prepared.proposal["runtime_identity"], profile.binding())

        deployments = [item for item in prepared.evidence if item.get("type") == "deployment_certificate"]
        self.assertEqual(len(deployments), 1)
        content = deployments[0]["content"]
        self.assertEqual(content["runtime_name"], "openhands")
        self.assertEqual(content["runtime_version"], PINNED_OPENHANDS_COMMIT)
        self.assertEqual(content["runtime_principal"], profile.principal)
        self.assertEqual(content["runtime_manifest_digest"], profile.runtime_manifest_digest)

    def test_execution_requires_separate_explicit_step(self) -> None:
        routed = self.adapter.route_event(self.mcp_event())
        permit_id = routed["claimsieve"]["permit_id"]
        self.assertEqual(len(self.workflow.ledger_records()["execution"]), 0)
        result = self.intake.execute_pending(permit_id, 51, 52)
        self.assertEqual(result.observation["reconciliation"], "CONFIRMED_SUCCESS")
        self.assertFalse(result.execution["automatic_retry_allowed"])
        self.assertGreaterEqual(len(self.workflow.ledger_records()["execution"]), 3)

    def test_runtime_version_substitution_is_rejected_before_authority(self) -> None:
        intent = self.adapter.build_intent(self.mcp_event()).to_dict()
        intent["runtime_version"] = "different-commit"
        with self.assertRaisesRegex(ClaimSieveIntakeError, "runtime version mismatch"):
            self.intake.route_intent(intent)
        self.assertEqual(self.intake.pending_permits(), ())

    def test_runtime_identity_substitution_is_rejected_before_authority(self) -> None:
        intent = self.adapter.build_intent(self.mcp_event()).to_dict()
        intent["runtime"] = "openclaw"
        with self.assertRaisesRegex(ClaimSieveIntakeError, "runtime identity mismatch"):
            self.intake.route_intent(intent)
        self.assertEqual(self.intake.pending_permits(), ())

    def test_action_kind_substitution_is_rejected_before_authority(self) -> None:
        intent = self.adapter.build_intent(self.mcp_event()).to_dict()
        intent["action_kind"] = "ExecuteBashAction"
        with self.assertRaisesRegex(ClaimSieveIntakeError, "unsupported OpenHands action capability"):
            self.intake.route_intent(intent)
        self.assertEqual(self.intake.pending_permits(), ())

    def test_tool_name_substitution_is_rejected_before_authority(self) -> None:
        intent = self.adapter.build_intent(self.mcp_event()).to_dict()
        intent["tool_name"] = "terminal"
        with self.assertRaisesRegex(ClaimSieveIntakeError, "unsupported OpenHands consequential tool"):
            self.intake.route_intent(intent)

    def test_authority_metadata_injection_is_rejected(self) -> None:
        intent = self.adapter.build_intent(self.mcp_event()).to_dict()
        intent["security_risk"] = "LOW"
        with self.assertRaisesRegex(ClaimSieveIntakeError, "exact authority intake schema"):
            self.intake.route_intent(intent)

    def test_unexpected_argument_and_context_fields_are_rejected(self) -> None:
        intent = self.adapter.build_intent(self.mcp_event()).to_dict()
        intent["arguments"]["token"] = "must-not-enter-authority"
        with self.assertRaisesRegex(ClaimSieveIntakeError, "arguments must be exactly"):
            self.intake.route_intent(intent)

        intent = self.adapter.build_intent(self.mcp_event("call-openhands-github-002")).to_dict()
        intent["context"]["approval"] = "self-approved"
        with self.assertRaisesRegex(ClaimSieveIntakeError, "context fields"):
            self.intake.route_intent(intent)

    def test_wrong_workflow_runtime_or_version_cannot_back_intake(self) -> None:
        wrong_runtime = FounderOSReferenceWorkflow(
            self.root / "wrong-runtime",
            allowed_repositories={self.repository},
            provider_mode="success",
            runtime_name="deepagents",
            runtime_version="0.7.9",
        )
        with self.assertRaisesRegex(ClaimSieveIntakeError, "bound to the openhands principal"):
            OpenHandsFounderIntake(wrong_runtime)

        wrong_version = FounderOSReferenceWorkflow(
            self.root / "wrong-version",
            allowed_repositories={self.repository},
            provider_mode="success",
            runtime_name="openhands",
            runtime_version="different-commit",
        )
        with self.assertRaisesRegex(ClaimSieveIntakeError, "pinned upstream commit"):
            OpenHandsFounderIntake(wrong_version)

    def test_post_approval_runtime_identity_mutation_is_rejected_by_executor(self) -> None:
        prepared = self.workflow.prepare_issue(self.direct_request("runtime-tamper"))
        prepared.proposal["runtime_identity"]["runtime_version"] = "different-commit"
        with self.assertRaises(PermitError):
            self.workflow.execute_issue(prepared, 51, 52)

    def test_post_approval_destination_or_parameter_mutation_is_rejected(self) -> None:
        prepared = self.workflow.prepare_issue(self.direct_request("destination-tamper"))
        prepared.proposal["action"]["destination"]["authority"] = "attacker/repository"
        with self.assertRaises(PermitError):
            self.workflow.execute_issue(prepared, 51, 52)

        prepared = self.workflow.prepare_issue(self.direct_request("parameter-tamper"))
        prepared.proposal["action"]["parameters"]["title"] = "Mutated after approval"
        with self.assertRaises(PermitError):
            self.workflow.execute_issue(prepared, 51, 52)

    def test_duplicate_tool_call_identity_is_rejected(self) -> None:
        intent = self.adapter.build_intent(self.mcp_event()).to_dict()
        receipt = self.intake.route_intent(intent)
        self.assertEqual(receipt["status"], "PERMIT_ISSUED_EXECUTION_PENDING")
        with self.assertRaisesRegex(ClaimSieveIntakeError, "duplicate OpenHands tool call identity"):
            self.intake.route_intent(self.adapter.build_intent(self.mcp_event()).to_dict())

    def test_concurrent_duplicate_tool_call_identity_admits_once(self) -> None:
        intent = self.adapter.build_intent(self.mcp_event()).to_dict()
        original_prepare = self.workflow.prepare_issue
        first_entered = threading.Event()
        release_first = threading.Event()

        def slow_prepare(request):
            first_entered.set()
            if not release_first.wait(timeout=5):
                raise RuntimeError("test synchronization timeout")
            return original_prepare(request)

        self.workflow.prepare_issue = slow_prepare  # type: ignore[method-assign]
        outcomes: list[str] = []
        errors: list[BaseException] = []

        def route() -> None:
            try:
                self.intake.route_intent(dict(intent))
                outcomes.append("admitted")
            except BaseException as exc:
                errors.append(exc)

        first = threading.Thread(target=route)
        second = threading.Thread(target=route)
        first.start()
        self.assertTrue(first_entered.wait(timeout=5))
        second.start()
        release_first.set()
        first.join(timeout=5)
        second.join(timeout=5)
        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual(outcomes, ["admitted"])
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], ClaimSieveIntakeError)
        self.assertIn("duplicate OpenHands tool call identity", str(errors[0]))

    def test_unknown_or_reused_pending_permit_cannot_execute(self) -> None:
        with self.assertRaisesRegex(ClaimSieveIntakeError, "unknown pending permit"):
            self.intake.execute_pending("permit:missing", 51, 52)

        routed = self.adapter.route_event(self.mcp_event())
        permit_id = routed["claimsieve"]["permit_id"]
        self.intake.execute_pending(permit_id, 51, 52)
        with self.assertRaisesRegex(ClaimSieveIntakeError, "already started"):
            self.intake.execute_pending(permit_id, 53, 54)


if __name__ == "__main__":
    unittest.main()
