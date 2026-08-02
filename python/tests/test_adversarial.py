from __future__ import annotations

import copy
import unittest

from claimsieve_ref.fixtures import evidence, policy, proposal
from claimsieve_ref.kernel import CampaignState, evaluate
from claimsieve_ref.model import display_digest, proposal_digest


class AdversarialTrajectoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.evidence = evidence(10)
        self.policy = policy()
        self.base = proposal(self.evidence, 10, approve=True)

    def evaluate_tag(self, tag: str) -> str:
        candidate = copy.deepcopy(self.base)
        candidate["risk_tags"] = [tag]
        if candidate.get("approval"):
            candidate["approval"]["proposal_digest"] = proposal_digest(candidate)
            candidate["approval"]["display_digest"] = display_digest(candidate)
        return evaluate(candidate, self.policy, self.evidence, CampaignState("campaign-001"), 10).document["verdict"]

    def test_incident_derived_tags(self) -> None:
        expected = {
            "DIRECT_EXECUTION_ATTEMPT": "SUSPEND_CAMPAIGN",
            "CREDENTIAL_USE": "SUSPEND_CAMPAIGN",
            "CLOUD_METADATA_ACCESS": "SUSPEND_CAMPAIGN",
            "OBSERVER_TAMPER": "SUSPEND_CAMPAIGN",
            "POLICY_TAMPER": "SUSPEND_CAMPAIGN",
            "CONTAINMENT_TAMPER": "SUSPEND_CAMPAIGN",
            "PRIVILEGE_ESCALATION": "SUSPEND_CAMPAIGN",
            "UNRESTRICTED_NESTED_AGENT": "SUSPEND_CAMPAIGN",
            "COVERT_RELAY": "SUSPEND_CAMPAIGN",
            "PRODUCTION_LATERAL_MOVE": "SUSPEND_CAMPAIGN",
            "CREDENTIAL_DISCOVERED": "QUARANTINE",
            "UNDECLARED_REDIRECT": "DENY",
            "PURPOSE_MISMATCH": "DENY",
            "EXECUTABLE_UPLOAD": "DENY",
            "PACKAGE_PROXY_TUNNEL": "DENY",
            "POST_APPROVAL_MUTATION": "DENY",
        }
        for tag, verdict in expected.items():
            with self.subTest(tag=tag):
                self.assertEqual(self.evaluate_tag(tag), verdict)

    def test_encoded_fragment_chain_trips_campaign(self) -> None:
        state = CampaignState("campaign-001")
        first = copy.deepcopy(self.base)
        first["risk_tags"] = ["ENCODED_FRAGMENT"]
        first["approval"]["proposal_digest"] = proposal_digest(first)
        first["approval"]["display_digest"] = display_digest(first)
        result1 = evaluate(first, self.policy, self.evidence, state, 10)
        self.assertEqual(result1.document["verdict"], "ALLOW")

        second = copy.deepcopy(first)
        second["proposal_id"] = "proposal-002"
        second["session_id"] = "session-002"
        second["approval"]["proposal_digest"] = proposal_digest(second)
        second["approval"]["display_digest"] = display_digest(second)
        result2 = evaluate(second, self.policy, self.evidence, result1.next_state, 11)
        self.assertEqual(result2.document["verdict"], "SUSPEND_CAMPAIGN")
        self.assertIn("ENCODED_FRAGMENT_CHAIN_DETECTED", result2.document["reason_codes"])

    def test_production_boundary_not_in_policy_is_denied(self) -> None:
        candidate = copy.deepcopy(self.base)
        candidate["action"]["destination"]["trust_domain"] = "production-other-company"
        candidate["approval"]["proposal_digest"] = proposal_digest(candidate)
        candidate["approval"]["display_digest"] = display_digest(candidate)
        result = evaluate(candidate, self.policy, self.evidence, CampaignState("campaign-001"), 10)
        self.assertEqual(result.document["verdict"], "DENY")
        self.assertIn("TRUST_DOMAIN_NOT_ALLOWED", result.document["reason_codes"])


if __name__ == "__main__":
    unittest.main()
