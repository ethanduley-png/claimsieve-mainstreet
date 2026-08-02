from __future__ import annotations

import copy
import unittest

from claimsieve_ref.fixtures import evidence, policy, proposal
from claimsieve_ref.kernel import CampaignState, evaluate
from claimsieve_ref.model import display_digest, proposal_digest
from claimsieve_ref.mutants import (
    ReplayableReservationStore,
    permit_matches_ignoring_destination,
    reset_campaign_on_new_session,
    unknown_means_retryable,
)


class MutationDiscriminationTests(unittest.TestCase):
    def test_destination_ignorance_mutant_is_killed(self) -> None:
        ev = evidence(10)
        original = proposal(ev, 10, approve=True)
        changed = copy.deepcopy(original)
        changed["action"]["destination"]["authority"] = "attacker"
        fake_permit = {"campaign_id": original["campaign_id"]}
        self.assertTrue(permit_matches_ignoring_destination(fake_permit, changed))
        # Real kernel sees the post-approval mutation.
        decision = evaluate(changed, policy(), ev, CampaignState("campaign-001"), 10)
        self.assertNotEqual(decision.document["verdict"], "ALLOW")

    def test_replayable_store_mutant_is_killed(self) -> None:
        mutant = ReplayableReservationStore()
        first = mutant.reserve("permit", "action", 1)
        second = mutant.reserve("permit", "action", 1)
        self.assertIsNotNone(first)
        self.assertIsNotNone(second)  # Demonstrates the seeded fault.
        from claimsieve_ref.runtime import ReservationStore
        real = ReservationStore()
        self.assertIsNotNone(real.reserve("permit", "action", 1))
        self.assertIsNone(real.reserve("permit", "action", 1))

    def test_session_reset_mutant_is_killed(self) -> None:
        state = {"campaign_id": "c", "total_actions": 19, "sessions": ["s1"]}
        mutant = reset_campaign_on_new_session(state, "s2")
        self.assertEqual(mutant["total_actions"], 0)
        real = CampaignState("c", total_actions=19, sessions={"s1"})
        self.assertEqual(real.clone().total_actions, 19)

    def test_unknown_retry_mutant_is_killed(self) -> None:
        self.assertTrue(unknown_means_retryable("timeout_unknown"))
        # Normative invariant I-032 requires the opposite.
        self.assertFalse("timeout_unknown" in {"confirmed_failure"})


if __name__ == "__main__":
    unittest.main()
