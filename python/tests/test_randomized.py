from __future__ import annotations

import copy
import random
import unittest

from claimsieve_ref.fixtures import evidence, keypairs, policy, proposal
from claimsieve_ref.kernel import CampaignState, evaluate
from claimsieve_ref.model import approval_signing_subject, display_digest, proposal_digest


class RandomizedConformanceTests(unittest.TestCase):
    def test_random_mutations_fail_closed_or_require_new_approval(self) -> None:
        rng = random.Random(30030)
        ev = evidence(10)
        pol = policy()
        base = proposal(ev, 10, approve=True)
        dangerous_tags = [
            "DIRECT_EXECUTION_ATTEMPT", "CREDENTIAL_USE", "CLOUD_METADATA_ACCESS",
            "OBSERVER_TAMPER", "UNRESTRICTED_NESTED_AGENT", "COVERT_RELAY",
            "UNDECLARED_REDIRECT", "PACKAGE_PROXY_TUNNEL", "EXECUTABLE_UPLOAD",
        ]
        allowed = 0
        rejected = 0
        for index in range(1000):
            candidate = copy.deepcopy(base)
            mutation = rng.randrange(9)
            if mutation == 0:
                candidate["action"]["destination"]["authority"] += str(index)
            elif mutation == 1:
                candidate["action"]["destination"]["trust_domain"] = f"unknown-{index}"
            elif mutation == 2:
                candidate["action"]["parameters"]["body"] += f" #{index}"
            elif mutation == 3:
                candidate["risk_tags"] = [rng.choice(dangerous_tags)]
            elif mutation == 4:
                candidate["objective"]["subgoal"] = f"unapproved-{index}"
            elif mutation == 5:
                candidate["action"]["effect_class"] = "credential_use"
            elif mutation == 6:
                candidate["schema_version"] = "claimsieve.proposal.future"
            elif mutation == 7:
                candidate["evidence_refs"] = []
            else:
                # Benign mutation with fresh exact approval should remain allowed.
                candidate["action"]["parameters"]["body"] = f"Safe bounded message {index}"
                candidate["approval"]["proposal_digest"] = proposal_digest(candidate)
                candidate["approval"]["display_digest"] = display_digest(candidate)
                candidate["approval"]["signature"] = keypairs()["approver"].sign(
                    "approval-v1", approval_signing_subject(candidate["approval"])
                )

            result = evaluate(candidate, pol, ev, CampaignState("campaign-001"), 10)
            if mutation == 8:
                self.assertEqual(result.document["verdict"], "ALLOW")
                allowed += 1
            else:
                self.assertNotEqual(result.document["verdict"], "ALLOW")
                rejected += 1
        self.assertGreater(allowed, 80)
        self.assertGreater(rejected, 800)


if __name__ == "__main__":
    unittest.main()
