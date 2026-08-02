from __future__ import annotations

import copy
import unittest

from claimsieve_ref.fixtures import evidence, policy, proposal
from claimsieve_ref.kernel import CampaignState, evaluate
from claimsieve_ref.model import display_digest, proposal_digest


class KernelTests(unittest.TestCase):
    def setUp(self) -> None:
        self.evidence = evidence(10)
        self.policy = policy()
        self.proposal = proposal(self.evidence, 10, approve=True)
        self.state = CampaignState("campaign-001")

    def test_valid_action_allowed(self) -> None:
        decision = evaluate(self.proposal, self.policy, self.evidence, self.state, 10)
        self.assertEqual(decision.document["verdict"], "ALLOW")
        self.assertEqual(decision.document["reason_codes"], ["ALL_GATES_PASSED"])

    def test_missing_approval_requires_human(self) -> None:
        candidate = proposal(self.evidence, 10, approve=False)
        decision = evaluate(candidate, self.policy, self.evidence, self.state, 10)
        self.assertEqual(decision.document["verdict"], "REQUIRE_HUMAN")

    def test_post_approval_destination_swap_is_denied(self) -> None:
        candidate = copy.deepcopy(self.proposal)
        candidate["action"]["destination"]["authority"] = "+15550000000"
        decision = evaluate(candidate, self.policy, self.evidence, self.state, 10)
        self.assertEqual(decision.document["verdict"], "DENY")
        self.assertTrue(
            {"APPROVAL_PROPOSAL_DIGEST_MISMATCH", "DESTINATION_EVIDENCE_MISMATCH"}
            & set(decision.document["reason_codes"])
        )

    def test_fresh_approval_after_mutation_can_be_considered(self) -> None:
        candidate = copy.deepcopy(self.proposal)
        candidate["action"]["parameters"]["body"] = "Updated but still bounded message"
        candidate["approval"]["proposal_digest"] = proposal_digest(candidate)
        candidate["approval"]["display_digest"] = display_digest(candidate)
        decision = evaluate(candidate, self.policy, self.evidence, self.state, 10)
        self.assertEqual(decision.document["verdict"], "ALLOW")

    def test_session_reset_does_not_reset_campaign_budget(self) -> None:
        state = self.state
        for index in range(3):
            candidate = proposal(self.evidence, 10 + index, approve=True, proposal_id=f"p-{index}", session_id=f"s-{index}")
            candidate["approval"]["proposal_digest"] = proposal_digest(candidate)
            candidate["approval"]["display_digest"] = display_digest(candidate)
            result = evaluate(candidate, self.policy, self.evidence, state, 10 + index)
            state = result.next_state
            self.assertEqual(result.document["verdict"], "ALLOW")
        candidate = proposal(self.evidence, 13, approve=True, proposal_id="p-3", session_id="s-3")
        candidate["approval"]["proposal_digest"] = proposal_digest(candidate)
        candidate["approval"]["display_digest"] = display_digest(candidate)
        result = evaluate(candidate, self.policy, self.evidence, state, 13)
        self.assertEqual(result.document["verdict"], "SUSPEND_CAMPAIGN")
        self.assertIn("CAMPAIGN_SESSION_BUDGET_EXCEEDED", result.document["reason_codes"])

    def test_denial_budget_suspends_on_the_action_that_exceeds_limit(self) -> None:
        strict_policy = policy(campaign_limits={**self.policy["campaign_limits"], "max_denials": 1})
        first = copy.deepcopy(self.proposal)
        first["risk_tags"] = ["PURPOSE_MISMATCH"]
        first_result = evaluate(first, strict_policy, self.evidence, self.state, 10)
        self.assertEqual(first_result.document["verdict"], "DENY")
        self.assertEqual(first_result.next_state.denials, 1)

        second = copy.deepcopy(self.proposal)
        second["proposal_id"] = "proposal-002"
        second["trace_id"] = "trace-002"
        second["session_id"] = "session-002"
        second["risk_tags"] = ["PURPOSE_MISMATCH"]
        second_result = evaluate(second, strict_policy, self.evidence, first_result.next_state, 11)
        self.assertEqual(second_result.document["verdict"], "SUSPEND_CAMPAIGN")
        self.assertIn("CAMPAIGN_DENIAL_BUDGET_EXCEEDED", second_result.document["reason_codes"] )
        self.assertEqual(second_result.next_state.denials, 2)
        self.assertEqual(second_result.next_state.status, "SUSPENDED")

    def test_credential_discovery_quarantines(self) -> None:
        candidate = copy.deepcopy(self.proposal)
        candidate["risk_tags"] = ["CREDENTIAL_DISCOVERED"]
        candidate["approval"]["proposal_digest"] = proposal_digest(candidate)
        candidate["approval"]["display_digest"] = display_digest(candidate)
        result = evaluate(candidate, self.policy, self.evidence, self.state, 10)
        self.assertEqual(result.document["verdict"], "QUARANTINE")

    def test_credential_use_suspends(self) -> None:
        candidate = copy.deepcopy(self.proposal)
        candidate["risk_tags"] = ["CREDENTIAL_USE"]
        result = evaluate(candidate, self.policy, self.evidence, self.state, 10)
        self.assertEqual(result.document["verdict"], "SUSPEND_CAMPAIGN")

    def test_unlisted_approver_key_is_denied(self) -> None:
        from claimsieve_ref.crypto import KeyPair
        from claimsieve_ref.model import approval_signing_subject

        rogue = KeyPair.from_seed("rogue-approver", b"R" * 32)
        candidate = copy.deepcopy(self.proposal)
        candidate["approval"]["approver_key_id"] = rogue.key_id
        candidate["approval"]["signature"] = rogue.sign(
            "approval-v1", approval_signing_subject(candidate["approval"])
        )
        result = evaluate(candidate, self.policy, self.evidence, self.state, 10)
        self.assertEqual(result.document["verdict"], "DENY")
        self.assertIn("APPROVER_KEY_NOT_ALLOWED", result.document["reason_codes"])

    def test_missing_evidence_fails_closed(self) -> None:
        result = evaluate(self.proposal, self.policy, [], self.state, 10)
        self.assertEqual(result.document["verdict"], "DENY")
        self.assertTrue(any(code.startswith("MISSING_EVIDENCE_") for code in result.document["reason_codes"]))

    def test_stale_evidence_fails_closed(self) -> None:
        old = evidence(0)
        candidate = proposal(old, 20, approve=True)
        result = evaluate(candidate, self.policy, old, self.state, 20)
        self.assertEqual(result.document["verdict"], "DENY")
        self.assertTrue(any(code.startswith("STALE_EVIDENCE_") for code in result.document["reason_codes"]))

    def test_malformed_approval_sequence_fails_closed(self) -> None:
        candidate = copy.deepcopy(self.proposal)
        candidate["approval"]["approved_at_seq"] = "not-an-integer"
        result = evaluate(candidate, self.policy, self.evidence, self.state, 10)
        self.assertEqual(result.document["verdict"], "DENY")
        self.assertIn("APPROVAL_SEQUENCE_INVALID", result.document["reason_codes"])

    def test_unknown_schema_fails_closed(self) -> None:
        candidate = copy.deepcopy(self.proposal)
        candidate["schema_version"] = "claimsieve.proposal.v999"
        result = evaluate(candidate, self.policy, self.evidence, self.state, 10)
        self.assertEqual(result.document["verdict"], "DENY")
        self.assertIn("UNSUPPORTED_PROPOSAL_SCHEMA", result.document["reason_codes"])

    def test_unallowed_principal_is_denied(self) -> None:
        candidate = copy.deepcopy(self.proposal)
        candidate["principal"] = "spiffe://attacker.invalid/agent"
        result = evaluate(candidate, self.policy, self.evidence, self.state, 10)
        self.assertEqual(result.document["verdict"], "DENY")
        self.assertIn("PRINCIPAL_NOT_ALLOWED", result.document["reason_codes"])

    def test_untrusted_evidence_source_is_denied(self) -> None:
        changed_evidence = copy.deepcopy(self.evidence)
        changed_evidence[0]["source"] = "spiffe://attacker.invalid/fake-crm"
        candidate = proposal(changed_evidence, 10, approve=True)
        result = evaluate(candidate, self.policy, changed_evidence, self.state, 10)
        self.assertEqual(result.document["verdict"], "DENY")
        self.assertIn(
            "UNTRUSTED_EVIDENCE_SOURCE_customer_contact_authority",
            result.document["reason_codes"],
        )

    def test_exact_destination_evidence_mismatch_is_denied(self) -> None:
        changed_evidence = copy.deepcopy(self.evidence)
        changed_evidence[1]["content"]["authority"] = "+15550000000"
        candidate = proposal(changed_evidence, 10, approve=True)
        result = evaluate(candidate, self.policy, changed_evidence, self.state, 10)
        self.assertEqual(result.document["verdict"], "DENY")
        self.assertIn("DESTINATION_EVIDENCE_MISMATCH", result.document["reason_codes"])

    def test_evidence_reference_omission_is_denied(self) -> None:
        candidate = copy.deepcopy(self.proposal)
        candidate["evidence_refs"] = candidate["evidence_refs"][:-1]
        candidate["approval"]["proposal_digest"] = proposal_digest(candidate)
        candidate["approval"]["display_digest"] = display_digest(candidate)
        result = evaluate(candidate, self.policy, self.evidence, self.state, 10)
        self.assertEqual(result.document["verdict"], "DENY")
        self.assertIn("EVIDENCE_REFERENCE_MISMATCH", result.document["reason_codes"])

    def test_duplicate_evidence_reference_is_denied(self) -> None:
        candidate = copy.deepcopy(self.proposal)
        candidate["evidence_refs"].append(candidate["evidence_refs"][0])
        candidate["approval"]["proposal_digest"] = proposal_digest(candidate)
        candidate["approval"]["display_digest"] = display_digest(candidate)
        result = evaluate(candidate, self.policy, self.evidence, self.state, 10)
        self.assertEqual(result.document["verdict"], "DENY")
        self.assertIn("EVIDENCE_REFERENCE_MISMATCH", result.document["reason_codes"])

    def test_unlisted_approver_identity_is_denied(self) -> None:
        candidate = copy.deepcopy(self.proposal)
        candidate["approval"]["approver"] = "spiffe://mainstreet.local/tenant-demo/human/other"
        result = evaluate(candidate, self.policy, self.evidence, self.state, 10)
        self.assertEqual(result.document["verdict"], "DENY")
        self.assertIn("APPROVER_IDENTITY_NOT_ALLOWED", result.document["reason_codes"])

    def test_boolean_approval_sequence_is_denied(self) -> None:
        candidate = copy.deepcopy(self.proposal)
        candidate["approval"]["approved_at_seq"] = True
        result = evaluate(candidate, self.policy, self.evidence, self.state, 10)
        self.assertEqual(result.document["verdict"], "DENY")
        self.assertIn("APPROVAL_SEQUENCE_INVALID", result.document["reason_codes"])

    def test_invalid_campaign_limit_policy_fails_closed(self) -> None:
        changed_policy = copy.deepcopy(self.policy)
        changed_policy["campaign_limits"]["max_actions"] = True
        result = evaluate(self.proposal, changed_policy, self.evidence, self.state, 10)
        self.assertEqual(result.document["verdict"], "DENY")
        self.assertIn("CAMPAIGN_LIMIT_POLICY_INVALID", result.document["reason_codes"])

    def test_invalid_decision_sequence_fails_closed(self) -> None:
        result = evaluate(self.proposal, self.policy, self.evidence, self.state, True)
        self.assertEqual(result.document["verdict"], "DENY")
        self.assertIn("INVALID_DECISION_SEQUENCE", result.document["reason_codes"])

    def test_malformed_proposal_structure_fails_closed(self) -> None:
        candidate = copy.deepcopy(self.proposal)
        candidate["action"] = "not-an-object"
        result = evaluate(candidate, self.policy, self.evidence, self.state, 10)
        self.assertEqual(result.document["verdict"], "DENY")
        self.assertIn("PROPOSAL_STRUCTURE_INVALID", result.document["reason_codes"])


if __name__ == "__main__":
    unittest.main()

class DeploymentAndEpochTests(unittest.TestCase):

    def test_multiple_active_deployment_certificates_deny(self) -> None:
        ev = evidence(10)
        ev.append(copy.deepcopy(ev[2]))
        prop = proposal(ev, 10, approve=True)
        result = evaluate(prop, policy(), ev, CampaignState("campaign-001"), 10)
        self.assertEqual(result.document["verdict"], "DENY")
        self.assertIn(
            "ACTIVE_DEPLOYMENT_CERTIFICATE_COUNT_INVALID",
            result.document["reason_codes"],
        )

    def test_multiple_active_governance_epochs_deny(self) -> None:
        ev = evidence(10)
        ev.append(copy.deepcopy(ev[3]))
        prop = proposal(ev, 10, approve=True)
        result = evaluate(prop, policy(), ev, CampaignState("campaign-001"), 10)
        self.assertEqual(result.document["verdict"], "DENY")
        self.assertIn(
            "ACTIVE_GOVERNANCE_EPOCH_COUNT_INVALID",
            result.document["reason_codes"],
        )
    def test_inactive_deployment_certificate_denies(self) -> None:
        ev = evidence(10)
        ev[2]["content"]["status"] = "REVOKED"
        prop = proposal(ev, 10, approve=True)
        result = evaluate(prop, policy(), ev, CampaignState("campaign-001"), 10)
        self.assertEqual(result.document["verdict"], "DENY")
        self.assertIn("DEPLOYMENT_CERTIFICATE_NOT_ACTIVE", result.document["reason_codes"])

    def test_governance_epoch_runtime_mismatch_denies(self) -> None:
        ev = evidence(10)
        ev[3]["content"]["runtime_manifest_digest"] = "sha256:" + "0" * 64
        prop = proposal(ev, 10, approve=True)
        result = evaluate(prop, policy(), ev, CampaignState("campaign-001"), 10)
        self.assertEqual(result.document["verdict"], "DENY")
        self.assertIn("GOVERNANCE_EPOCH_RUNTIME_MISMATCH", result.document["reason_codes"])
