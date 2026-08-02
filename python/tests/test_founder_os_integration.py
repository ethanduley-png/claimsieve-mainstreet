from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from claimsieve_ref.durable_state import DurableStateError
from claimsieve_ref.kernel import evaluate
from claimsieve_ref.model import proposal_digest
from claimsieve_ref.runtime import PermitError
from founder_os import (
    FounderOSInputError,
    FounderOSReferenceWorkflow,
    GitHubIssueRequest,
    founder_evidence,
    founder_fixture_keys,
    founder_policy,
    founder_proposal,
)


class FounderOSIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.repository = "example/claimsieve-mainstreet"
        self.request = GitHubIssueRequest(
            proposal_id="founder-proposal-001",
            trace_id="founder-trace-001",
            campaign_id="founder-campaign-001",
            session_id="founder-session-001",
            work_item_id="work-item-001",
            repository=self.repository,
            title="Review Founder OS integration",
            body="Inspect exact action binding and unknown outcomes.",
            requested_at_seq=10,
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def workflow(self, mode: str = "success") -> FounderOSReferenceWorkflow:
        return FounderOSReferenceWorkflow(
            self.root / mode,
            allowed_repositories={self.repository},
            provider_mode=mode,
        )

    def test_valid_issue_uses_v033_authority_and_independent_observer(self) -> None:
        workflow = self.workflow()
        prepared = workflow.prepare_issue(self.request)
        result = workflow.execute_issue(prepared, 11, 12)
        self.assertEqual(prepared.decision["verdict"], "ALLOW")
        self.assertEqual(result.observation["reconciliation"], "CONFIRMED_SUCCESS")
        self.assertFalse(result.execution["automatic_retry_allowed"])
        self.assertTrue(all(not errors for errors in workflow.verify_ledgers().values()))

    def test_repository_outside_founder_allowlist_is_blocked_before_authority(self) -> None:
        workflow = self.workflow()
        changed = GitHubIssueRequest(**{**self.request.__dict__, "repository": "attacker/other"})
        with self.assertRaisesRegex(FounderOSInputError, "allowlist"):
            workflow.prepare_issue(changed)

    def test_repository_substitution_after_approval_is_blocked(self) -> None:
        workflow = self.workflow()
        prepared = workflow.prepare_issue(self.request)
        changed = copy.deepcopy(prepared.proposal)
        changed["action"]["destination"]["authority"] = "attacker/other"
        with self.assertRaisesRegex(DurableStateError, "binding mismatch"):
            workflow._executor.execute(
                prepared.permit,
                changed,
                prepared.signed_policy,
                prepared.evidence,
                prepared.decision,
                11,
            )

    def test_title_mutation_after_approval_is_blocked(self) -> None:
        workflow = self.workflow()
        prepared = workflow.prepare_issue(self.request)
        changed = copy.deepcopy(prepared.proposal)
        changed["action"]["parameters"]["title"] = "Mutated title"
        with self.assertRaisesRegex(DurableStateError, "binding mismatch"):
            workflow._executor.execute(
                prepared.permit,
                changed,
                prepared.signed_policy,
                prepared.evidence,
                prepared.decision,
                11,
            )

    def test_body_mutation_after_approval_is_blocked(self) -> None:
        workflow = self.workflow()
        prepared = workflow.prepare_issue(self.request)
        changed = copy.deepcopy(prepared.proposal)
        changed["action"]["parameters"]["body"] = "Mutated body"
        with self.assertRaisesRegex(DurableStateError, "binding mismatch"):
            workflow._executor.execute(
                prepared.permit,
                changed,
                prepared.signed_policy,
                prepared.evidence,
                prepared.decision,
                11,
            )

    def test_missing_work_item_evidence_is_denied(self) -> None:
        keys = founder_fixture_keys()
        policy = founder_policy(keys)
        evidence = founder_evidence(self.request, keys)
        missing = [item for item in evidence if item["type"] != "work_item_authority"]
        proposal = founder_proposal(self.request, missing, keys)
        decision = evaluate(
            proposal,
            policy,
            missing,
            self.workflow()._state.read_campaign(self.request.campaign_id).state,
            10,
        )
        self.assertEqual(decision.document["verdict"], "DENY")
        self.assertIn("MISSING_EVIDENCE_work_item_authority", decision.document["reason_codes"])

    def test_repository_registry_must_bind_exact_repository(self) -> None:
        keys = founder_fixture_keys()
        policy = founder_policy(keys)
        evidence = founder_evidence(self.request, keys)
        tampered = copy.deepcopy(evidence)
        registry = next(item for item in tampered if item["type"] == "destination_registry")
        registry["content"]["authority"] = "other/repository"
        # Signature tampering must fail at authority verification. Kernel also denies exact destination mismatch.
        proposal = founder_proposal(self.request, tampered, keys)
        decision = evaluate(
            proposal,
            policy,
            tampered,
            self.workflow()._state.read_campaign(self.request.campaign_id).state,
            10,
        )
        self.assertEqual(decision.document["verdict"], "DENY")
        self.assertIn("DESTINATION_EVIDENCE_MISMATCH", decision.document["reason_codes"])

    def test_stale_approval_is_rejected(self) -> None:
        workflow = self.workflow()
        prepared = workflow.prepare_issue(self.request)
        stale = copy.deepcopy(prepared.proposal)
        stale["approval"]["expires_at_seq"] = 9
        self.assertNotEqual(proposal_digest(stale), "")
        with self.assertRaises((PermitError, DurableStateError)):
            workflow._executor.execute(
                prepared.permit,
                stale,
                prepared.signed_policy,
                prepared.evidence,
                prepared.decision,
                11,
            )

    def test_policy_substitution_is_rejected(self) -> None:
        workflow = self.workflow()
        prepared = workflow.prepare_issue(self.request)
        substituted = copy.deepcopy(prepared.signed_policy)
        substituted["policy"]["version"] = 2
        with self.assertRaisesRegex(DurableStateError, "policy|signature|binding"):
            workflow._executor.execute(
                prepared.permit,
                prepared.proposal,
                substituted,
                prepared.evidence,
                prepared.decision,
                11,
            )

    def test_permit_replay_is_blocked(self) -> None:
        workflow = self.workflow()
        prepared = workflow.prepare_issue(self.request)
        workflow.execute_issue(prepared, 11, 12)
        with self.assertRaisesRegex(DurableStateError, "replay|duplicate"):
            workflow.execute_issue(prepared, 13, 14)

    def test_timeout_before_commit_remains_unknown(self) -> None:
        workflow = self.workflow("timeout_before_commit")
        prepared = workflow.prepare_issue(self.request)
        result = workflow.execute_issue(prepared, 11, 12)
        self.assertEqual(result.observation["reconciliation"], "OUTCOME_UNKNOWN")
        self.assertFalse(result.execution["automatic_retry_allowed"])

    def test_timeout_after_commit_is_reconciled_independently(self) -> None:
        workflow = self.workflow("timeout_after_commit")
        prepared = workflow.prepare_issue(self.request)
        result = workflow.execute_issue(prepared, 11, 12)
        self.assertEqual(result.execution["executor_receipt"]["provider_status"], "timeout_unknown")
        self.assertEqual(result.observation["reconciliation"], "CONFIRMED_SUCCESS")
        self.assertFalse(result.execution["automatic_retry_allowed"])

    def test_bad_repository_shape_is_rejected(self) -> None:
        changed = GitHubIssueRequest(**{**self.request.__dict__, "repository": "https://github.com/example/repo"})
        with self.assertRaisesRegex(FounderOSInputError, "owner/name"):
            changed.validate()


if __name__ == "__main__":
    unittest.main()
