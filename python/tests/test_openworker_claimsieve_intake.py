from __future__ import annotations

import tempfile
import threading
import unittest
from pathlib import Path

from claimsieve_ref.runtime import PermitError
from founder_os import FounderOSReferenceWorkflow, GitHubIssueRequest
from mainstreet_runtimes import ClaimSieveRuntimeContext
from mainstreet_runtimes.openworker_adapter import OpenWorkerProposalAdapter
from mainstreet_runtimes.openworker_claimsieve_intake import (
    OpenWorkerFounderIntake,
    OpenWorkerIntakeError,
)


OPENWORKER_COMMIT = "86c57f0692a5a318e55d1b9e0188d798b9fc5690"


class OpenWorkerClaimSieveIntakeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.repository = "example/claimsieve-mainstreet"
        self.workflow = FounderOSReferenceWorkflow(
            self.root,
            allowed_repositories={self.repository},
            provider_mode="success",
            runtime_name="openworker",
            runtime_version=OPENWORKER_COMMIT,
        )
        self.intake = OpenWorkerFounderIntake(self.workflow)
        self.context = ClaimSieveRuntimeContext(
            trace_id="trace-openworker-001",
            campaign_id="campaign-openworker-001",
            session_id="session-openworker-001",
            work_item_id="work-openworker-001",
            requested_at_seq=50,
        )
        self.adapter = OpenWorkerProposalAdapter(
            self.context,
            self.intake.route_intent,
            consequential_tools={"create_github_issue"},
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def tool_call(self) -> dict:
        return {
            "schema_version": "mainstreet.openworker_tool_call.v1",
            "id": "ow-call-github-001",
            "name": "create_github_issue",
            "arguments": {
                "repository": self.repository,
                "title": "Review OpenWorker ClaimSieve intake",
                "body": "Permit issuance remains separate from provider execution.",
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
            title="Verify OpenWorker runtime binding",
            body="The permit and deployment evidence must bind the pinned OpenWorker runtime.",
            requested_at_seq=50,
        )

    def test_intent_reaches_authority_but_stops_before_execution(self) -> None:
        routed = self.adapter.route_tool_call(self.tool_call())
        receipt = routed["claimsieve"]
        self.assertEqual(receipt["status"], "PERMIT_ISSUED_EXECUTION_PENDING")
        self.assertEqual(receipt["runtime_name"], "openworker")
        self.assertEqual(receipt["runtime_version"], OPENWORKER_COMMIT)
        self.assertEqual(
            receipt["runtime_principal"],
            "spiffe://mainstreet.local/tenant-founder/agent/openworker",
        )
        self.assertFalse(receipt["external_action_executed"])
        self.assertFalse(routed["external_action_executed"])
        self.assertEqual(len(self.workflow.ledger_records()["execution"]), 0)

    def test_runtime_identity_is_bound_into_permit_and_signed_evidence(self) -> None:
        prepared = self.workflow.prepare_issue(self.direct_request("identity"))
        principal = "spiffe://mainstreet.local/tenant-founder/agent/openworker"
        self.assertEqual(prepared.proposal["principal"], principal)
        self.assertEqual(prepared.permit["principal"], principal)
        self.assertEqual(prepared.proposal["runtime_identity"], self.workflow.runtime_profile.binding())
        deployments = [item for item in prepared.evidence if item.get("type") == "deployment_certificate"]
        self.assertEqual(len(deployments), 1)
        self.assertEqual(deployments[0]["content"]["runtime_version"], OPENWORKER_COMMIT)

    def test_execution_requires_separate_explicit_step(self) -> None:
        routed = self.adapter.route_tool_call(self.tool_call())
        permit_id = routed["claimsieve"]["permit_id"]
        result = self.intake.execute_pending(permit_id, 51, 52)
        self.assertEqual(result.observation["reconciliation"], "CONFIRMED_SUCCESS")
        self.assertFalse(result.execution["automatic_retry_allowed"])

    def test_wrong_runtime_version_is_rejected(self) -> None:
        workflow = FounderOSReferenceWorkflow(
            self.root / "wrong-version",
            allowed_repositories={self.repository},
            provider_mode="success",
            runtime_name="openworker",
            runtime_version="different-commit",
        )
        with self.assertRaisesRegex(OpenWorkerIntakeError, "pinned upstream commit"):
            OpenWorkerFounderIntake(workflow)

    def test_runtime_substitution_is_rejected(self) -> None:
        intent = self.adapter.build_intent(self.tool_call()).to_dict()
        intent["runtime"] = "deepagents"
        with self.assertRaisesRegex(OpenWorkerIntakeError, "runtime identity mismatch"):
            self.intake.route_intent(intent)

    def test_intent_field_smuggling_is_rejected(self) -> None:
        intent = self.adapter.build_intent(self.tool_call()).to_dict()
        intent["approval"] = "allow"
        with self.assertRaisesRegex(OpenWorkerIntakeError, "intent fields"):
            self.intake.route_intent(intent)
        self.assertEqual(self.intake.pending_permits(), ())

    def test_duplicate_tool_call_identity_is_rejected(self) -> None:
        intent = self.adapter.build_intent(self.tool_call()).to_dict()
        self.intake.route_intent(intent)
        with self.assertRaisesRegex(OpenWorkerIntakeError, "duplicate OpenWorker tool call identity"):
            self.intake.route_intent(dict(intent))

    def test_concurrent_duplicate_admission_allows_exactly_one(self) -> None:
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
        self.assertEqual(outcomes, ["admitted"])
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], OpenWorkerIntakeError)

    def test_post_permit_runtime_identity_mutation_fails_at_execution(self) -> None:
        prepared = self.workflow.prepare_issue(self.direct_request("runtime-tamper"))
        prepared.proposal["runtime_identity"]["runtime_version"] = "mutated"
        with self.assertRaises(PermitError):
            self.workflow.execute_issue(prepared, 51, 52)


if __name__ == "__main__":
    unittest.main()
