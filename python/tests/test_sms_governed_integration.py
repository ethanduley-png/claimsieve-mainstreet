"""Consent-bound SMS action traverses existing ClaimSieve authorities without egress.

This exercises the entire durable Python reference boundary, not a live SMS
provider, and asserts that changing the approved text cannot reach the adapter.
"""
from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from claimsieve_ref.durable_state import (
    DurableCampaignStateStore,
    DurableExecutor,
    DurableStateService,
    IndependentObserver,
)
from claimsieve_ref.fixtures import evidence, keypairs, policy, proposal, signed_policy
from claimsieve_ref.kernel import evaluate
from claimsieve_ref.runtime import Authority, PermitError
from claimsieve_ref.sms_sandbox_provider import SandboxSMSProvider


class GovernedSMSTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        base = Path(temporary.name)
        self.keys = keypairs()
        self.state = DurableStateService(
            base / "state.sqlite",
            executor_keys={self.keys["executor"].key_id: self.keys["executor"].public},
            observer_keys={self.keys["observer"].key_id: self.keys["observer"].public},
        )
        self.provider = SandboxSMSProvider(
            base / "no_send_provider.sqlite",
            allowed_recipients={"+15551234567"},
            allowed_resources={"lead-123"},
        )
        self.ev = evidence(10)
        sample_action = copy.deepcopy(proposal(self.ev, 10)["action"])
        sample_action["reversibility"] = "irreversible"
        self.prop = proposal(self.ev, 10, action=sample_action)
        self.signed = signed_policy()
        self.decision = evaluate(
            self.prop, policy(), self.ev,
            self.state.read_campaign(self.prop["campaign_id"]).state, 10,
        )
        self.authority = Authority(
            self.keys["authority"],
            {self.keys["approver"].key_id: self.keys["approver"].public},
            {self.keys["policy_authority"].key_id: self.keys["policy_authority"].public},
            {
                self.keys[name].key_id: self.keys[name].public
                for name in ("crm_evidence", "registry_evidence",
                             "deployment_evidence", "epoch_evidence")
            },
            DurableCampaignStateStore(self.state),
        )
        self.permit = self.authority.issue(
            self.prop, self.signed, self.ev, self.decision.document,
            10, nonce="11" * 24,
        )
        self.executor = DurableExecutor(
            self.state, self.provider,
            {self.keys["authority"].key_id: self.keys["authority"].public},
            self.keys["executor"],
        )
        self.observer = IndependentObserver(
            self.state, self.provider, self.keys["observer"],
        )

    def test_consent_authority_and_approval_to_observed_sandbox_effect(self) -> None:
        self.assertEqual(self.decision.document["verdict"], "ALLOW")
        result = self.executor.execute(
            self.permit, self.prop, self.signed, self.ev,
            self.decision.document, 11,
        )
        self.assertFalse(result["automatic_retry_allowed"])
        reservation = result["reservation"]["reservation_id"]
        observation = self.observer.reconcile(reservation, self.prop, 12)
        self.assertEqual(observation["reconciliation"], "CONFIRMED_SUCCESS")
        self.assertEqual(self.state.get_reservation(reservation)["outcome"], "CONFIRMED_SUCCESS")
        self.assertTrue(self.state.verify_journal())
        self.assertEqual(len(self.state.recovery_queue()), 0)

    def test_text_substitution_is_blocked_before_external_effect(self) -> None:
        modified = copy.deepcopy(self.prop)
        modified["action"]["parameters"]["body"] = "Unauthorized substituted message."
        with self.assertRaises((PermitError, ValueError)):
            self.executor.execute(
                self.permit, modified, self.signed, self.ev,
                self.decision.document, 11,
            )
        self.assertFalse(self.provider.query(self.permit["permit_id"]) is not None)


if __name__ == "__main__":
    unittest.main()
