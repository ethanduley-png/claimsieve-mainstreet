from __future__ import annotations

import tempfile
import threading
import unittest
from pathlib import Path

from claimsieve_ref.runtime import PermitError
from founder_os import FounderOSReferenceWorkflow, GitHubIssueRequest
from mainstreet_runtimes import ClaimSieveRuntimeContext, DeepAgentsProposalAdapter
from mainstreet_runtimes.claimsieve_intake import ClaimSieveIntakeError, DeepAgentsFounderIntake


class DeepAgentsClaimSieveIntakeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.repository = "example/claimsieve-mainstreet"
        self.workflow = FounderOSReferenceWorkflow(
            self.root,
            allowed_repositories={self.repository},
            provider_mode="success",
            runtime_name="deepagents",
            runtime_version="0.7.9",
        )
        self.intake = DeepAgentsFounderIntake(self.workflow)
        self.context = ClaimSieveRuntimeContext(
            trace_id="trace-intake-001",
            campaign_id="campaign-intake-001",
            session_id="session-intake-001",
            work_item_id="work-intake-001",
            requested_at_seq=40,
        )
        self.adapter = DeepAgentsProposalAdapter(
            self.context,
            self.intake.route_intent,
            consequential_tools={"create_github_issue"},
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def tool_call(self) -> dict:
        return {
            "id": "call-github-001",
            "name": "create_github_issue",
            "args": {
                "repository": self.repository,
                "title": "Review Deep Agents ClaimSieve intake",
                "body": "Permit issuance must remain separate from provider execution.",
            },
        }

    def direct_request(self, suffix: str = "direct") -> GitHubIssueRequest:
        return GitHubIssueRequest(
            proposal_id=f"proposal-{suffix}",
            trace_id=f"trace-{suffix}",
            campaign_id=f"campaign-{suffix}",
            session_id=f"session-{suffix}",
            work_item_id=f"work-{suffix}",
            repository=self.repository,
            title="Verify Deep Agents runtime binding",
            body="The permit principal and signed deployment evidence must identify Deep Agents.",
            requested_at_seq=40,
        )

    def test_intent_reaches_existing_authority_but_stops_before_execution(self) -> None:
        routed = self.adapter.route_tool_call(self.tool_call())
        receipt = routed["claimsieve"]
        self.assertEqual(receipt["status"], "PERMIT_ISSUED_EXECUTION_PENDING")
        self.assertEqual(receipt["runtime_name"], "deepagents")
        self.assertEqual(receipt["runtime_version"], "0.7.9")
        self.assertEqual(
            receipt["runtime_principal"],
            "spiffe://mainstreet.local/tenant-founder/agent/deepagents",
        )
        self.assertTrue(receipt["runtime_manifest_digest"].startswith("sha256:"))
        self.assertFalse(receipt["external_action_executed"])
        self.assertFalse(routed["external_action_executed"])
        self.assertEqual(len(self.workflow.ledger_records()["execution"]), 0)
        self.assertEqual(self.intake.pending_permits(), (receipt["permit_id"],))

    def test_existing_authority_issues_deepagents_principal_and_signed_runtime_evidence(self) -> None:
        prepared = self.workflow.prepare_issue(self.direct_request("identity"))
        principal = "spiffe://mainstreet.local/tenant-founder/agent/deepagents"
        self.assertEqual(prepared.proposal["principal"], principal)
        self.assertEqual(prepared.permit["principal"], principal)
        self.assertEqual(prepared.policy["allowed_principals"], [principal])
        self.assertEqual(prepared.proposal["runtime_identity"], self.workflow.runtime_profile.binding())

        deployments = [item for item in prepared.evidence if item.get("type") == "deployment_certificate"]
        self.assertEqual(len(deployments), 1)
        deployment = deployments[0]
        self.assertEqual(deployment["content"]["runtime_name"], "deepagents")
        self.assertEqual(deployment["content"]["runtime_version"], "0.7.9")
        self.assertEqual(deployment["content"]["runtime_principal"], principal)
        self.assertEqual(
            deployment["content"]["runtime_manifest_digest"],
            self.workflow.runtime_profile.runtime_manifest_digest,
        )

    def test_execution_requires_separate_explicit_step(self) -> None:
        routed = self.adapter.route_tool_call(self.tool_call())
        permit_id = routed["claimsieve"]["permit_id"]
        result = self.intake.execute_pending(permit_id, 41, 42)
        self.assertEqual(result.observation["reconciliation"], "CONFIRMED_SUCCESS")
        self.assertFalse(result.execution["automatic_retry_allowed"])
        self.assertGreaterEqual(len(self.workflow.ledger_records()["execution"]), 3)

    def test_post_approval_runtime_identity_mutation_is_rejected_by_executor(self) -> None:
        prepared = self.workflow.prepare_issue(self.direct_request("runtime-tamper"))
        prepared.proposal["runtime_identity"]["runtime_version"] = "0.7.8"
        with self.assertRaises(PermitError):
            self.workflow.execute_issue(prepared, 41, 42)

    def test_runtime_identity_substitution_is_rejected(self) -> None:
        intent = self.adapter.build_intent(self.tool_call()).to_dict()
        intent["runtime"] = "openclaw"
        with self.assertRaisesRegex(ClaimSieveIntakeError, "runtime identity mismatch"):
            self.intake.route_intent(intent)

    def test_openclaw_workflow_cannot_back_deepagents_intake(self) -> None:
        other_root = self.root / "openclaw"
        workflow = FounderOSReferenceWorkflow(
            other_root,
            allowed_repositories={self.repository},
            provider_mode="success",
        )
        with self.assertRaisesRegex(ClaimSieveIntakeError, "bound to the deepagents principal"):
            DeepAgentsFounderIntake(workflow)

    def test_wrong_deepagents_version_cannot_back_pinned_intake(self) -> None:
        other_root = self.root / "wrong-version"
        workflow = FounderOSReferenceWorkflow(
            other_root,
            allowed_repositories={self.repository},
            provider_mode="success",
            runtime_name="deepagents",
            runtime_version="0.7.8",
        )
        with self.assertRaisesRegex(ClaimSieveIntakeError, "pinned adapter version"):
            DeepAgentsFounderIntake(workflow)

    def test_unexpected_argument_is_rejected_before_authority(self) -> None:
        intent = self.adapter.build_intent(self.tool_call()).to_dict()
        intent["arguments"]["token"] = "must-not-enter-authority"
        with self.assertRaisesRegex(ClaimSieveIntakeError, "arguments must be exactly"):
            self.intake.route_intent(intent)
        self.assertEqual(self.intake.pending_permits(), ())

    def test_duplicate_tool_call_identity_is_rejected(self) -> None:
        first = self.adapter.build_intent(self.tool_call()).to_dict()
        receipt = self.intake.route_intent(first)
        self.assertEqual(receipt["status"], "PERMIT_ISSUED_EXECUTION_PENDING")
        second = self.adapter.build_intent(self.tool_call()).to_dict()
        with self.assertRaisesRegex(ClaimSieveIntakeError, "duplicate Deep Agents tool call identity"):
            self.intake.route_intent(second)

    def test_concurrent_duplicate_tool_call_identity_admits_once(self) -> None:
        intent = self.adapter.build_intent(self.tool_call()).to_dict()
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
            except BaseException as exc:  # test captures the competing path
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
        self.assertIn("duplicate Deep Agents tool call identity", str(errors[0]))

    def test_unknown_permit_cannot_be_executed(self) -> None:
        with self.assertRaisesRegex(ClaimSieveIntakeError, "unknown pending permit"):
            self.intake.execute_pending("permit:missing", 41, 42)

    def test_pending_permit_cannot_start_execution_twice(self) -> None:
        routed = self.adapter.route_tool_call(self.tool_call())
        permit_id = routed["claimsieve"]["permit_id"]
        self.intake.execute_pending(permit_id, 41, 42)
        with self.assertRaisesRegex(ClaimSieveIntakeError, "already started"):
            self.intake.execute_pending(permit_id, 43, 44)


if __name__ == "__main__":
    unittest.main()
