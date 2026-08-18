from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from claimsieve_ref.durable_state import DurableStateError
from founder_os import FounderOSReferenceWorkflow, GitHubIssueRequest


class OpenExecutionAssuranceProfileTests(unittest.TestCase):
    """Provider-neutral behavioral conformance tests over the v0.34 reference path.

    These tests intentionally reuse the existing Founder OS GitHub-issue slice as
    a concrete adapter. The invariants being tested are execution-assurance
    invariants and do not depend on GitHub-specific success semantics.
    """

    REQUIRED_INVARIANTS = {
        "OEA-001",
        "OEA-002",
        "OEA-003",
        "OEA-004",
        "OEA-005",
        "OEA-006",
        "OEA-007",
        "OEA-008",
    }

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.repository = "example/claimsieve-conformance"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def request(self, suffix: str = "001", seq: int = 10) -> GitHubIssueRequest:
        return GitHubIssueRequest(
            proposal_id=f"oea-proposal-{suffix}",
            trace_id=f"oea-trace-{suffix}",
            campaign_id=f"oea-campaign-{suffix}",
            session_id=f"oea-session-{suffix}",
            work_item_id=f"oea-work-{suffix}",
            repository=self.repository,
            title="Exercise the open execution assurance profile",
            body="Verify exact authority, independent outcome, and fail-closed semantics.",
            requested_at_seq=seq,
        )

    def workflow(self, mode: str = "success", suffix: str = "001") -> FounderOSReferenceWorkflow:
        return FounderOSReferenceWorkflow(
            self.root / f"{mode}-{suffix}",
            allowed_repositories={self.repository},
            provider_mode=mode,
        )

    def test_profile_vector_declares_the_required_candidate_invariants(self) -> None:
        root = Path(__file__).resolve().parents[2]
        profile = json.loads(
            (root / "vectors" / "execution_assurance_profile_v1.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            profile["schema_version"],
            "claimsieve.execution_assurance_profile.v1",
        )
        declared = {item["id"] for item in profile["invariants"]}
        self.assertEqual(declared, self.REQUIRED_INVARIANTS)

    def test_oea_001_proposal_and_allow_decision_are_not_authority_without_valid_permit(self) -> None:
        workflow = self.workflow()
        prepared = workflow.prepare_issue(self.request())
        invalid_permit = copy.deepcopy(prepared.permit)
        invalid_permit["signature"] = "ed25519:AAAA"
        with self.assertRaises(DurableStateError):
            workflow._executor.execute(
                invalid_permit,
                prepared.proposal,
                prepared.signed_policy,
                prepared.evidence,
                prepared.decision,
                11,
            )

    def test_oea_002_permit_rejects_post_authorization_destination_and_parameter_mutation(self) -> None:
        for field in ("destination", "parameter"):
            with self.subTest(field=field):
                workflow = self.workflow(suffix=field)
                prepared = workflow.prepare_issue(self.request(field))
                changed = copy.deepcopy(prepared.proposal)
                if field == "destination":
                    changed["action"]["destination"]["authority"] = "attacker/other"
                else:
                    changed["action"]["parameters"]["title"] = "Mutated after authorization"
                with self.assertRaises(DurableStateError):
                    workflow._executor.execute(
                        prepared.permit,
                        changed,
                        prepared.signed_policy,
                        prepared.evidence,
                        prepared.decision,
                        11,
                    )

    def test_oea_003_permit_is_one_use_logical_authority(self) -> None:
        workflow = self.workflow()
        prepared = workflow.prepare_issue(self.request())
        workflow.execute_issue(prepared, 11, 12)
        with self.assertRaises(DurableStateError):
            workflow.execute_issue(prepared, 13, 14)

    def test_oea_004_ambiguous_transport_remains_unknown(self) -> None:
        workflow = self.workflow("timeout_before_commit")
        prepared = workflow.prepare_issue(self.request())
        result = workflow.execute_issue(prepared, 11, 12)
        self.assertEqual(result.observation["schema_version"], "claimsieve.observer_receipt.v2")
        self.assertEqual(result.observation["reconciliation"], "OUTCOME_UNKNOWN")
        self.assertIsNone(result.observation["provider_record_digest"])
        self.assertFalse(result.execution["automatic_retry_allowed"])

    def test_oea_005_independent_readback_can_resolve_executor_timeout(self) -> None:
        workflow = self.workflow("timeout_after_commit")
        prepared = workflow.prepare_issue(self.request())
        result = workflow.execute_issue(prepared, 11, 12)
        self.assertEqual(result.execution["executor_receipt"]["provider_status"], "timeout_unknown")
        self.assertEqual(result.observation["reconciliation"], "CONFIRMED_SUCCESS")
        self.assertIsNotNone(result.observation["provider_record_digest"])
        self.assertIsNotNone(result.observation["observed_action_digest"])
        self.assertFalse(result.observation["receipt_conflict"])

    def test_oea_006_divergent_effect_is_detected(self) -> None:
        workflow = self.workflow("divergent", suffix="detect")
        prepared = workflow.prepare_issue(self.request("detect"))
        result = workflow.execute_issue(prepared, 11, 12)
        self.assertEqual(result.observation["reconciliation"], "DIVERGENT_EFFECT")
        self.assertIsNotNone(result.observation["provider_record_digest"])
        self.assertIsNotNone(result.observation["observed_action_digest"])

    def test_oea_006_durable_reference_contains_divergent_campaign(self) -> None:
        """Independent divergence atomically suspends the durable campaign."""
        workflow = self.workflow("divergent", suffix="contain")
        request = self.request("contain")
        prepared = workflow.prepare_issue(request)
        result = workflow.execute_issue(prepared, 11, 12)
        self.assertEqual(result.observation["reconciliation"], "DIVERGENT_EFFECT")
        self.assertEqual(workflow._state.read_campaign(request.campaign_id).state.status, "SUSPENDED")

    def test_oea_007_no_outcome_grants_automatic_logical_retry(self) -> None:
        for mode, expected in (
            ("success", "CONFIRMED_SUCCESS"),
            ("timeout_before_commit", "OUTCOME_UNKNOWN"),
            ("divergent", "DIVERGENT_EFFECT"),
        ):
            with self.subTest(mode=mode):
                workflow = self.workflow(mode, suffix=mode)
                prepared = workflow.prepare_issue(self.request(mode))
                result = workflow.execute_issue(prepared, 11, 12)
                self.assertEqual(result.observation["reconciliation"], expected)
                self.assertFalse(result.execution["automatic_retry_allowed"])

    def test_oea_008_four_separate_ledger_chains_verify(self) -> None:
        workflow = self.workflow()
        prepared = workflow.prepare_issue(self.request())
        workflow.execute_issue(prepared, 11, 12)
        verification = workflow.verify_ledgers()
        self.assertEqual(set(verification), {"proposal", "evidence", "decision", "execution"})
        self.assertTrue(all(not errors for errors in verification.values()))


if __name__ == "__main__":
    unittest.main()
