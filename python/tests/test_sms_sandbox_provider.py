from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from claimsieve_ref.durable_state import DispatchTicket
from claimsieve_ref.sms_sandbox_provider import SMSBoundaryError, SandboxSMSProvider


def action(recipient="+15551234567", body="Your appointment request was received."):
    return {
        "kind": "send_message", "effect_class": "external_write",
        "destination": {
            "scheme": "sms", "authority": recipient,
            "resource": "lead-123", "trust_domain": "sms-provider",
        },
        "method": "SEND", "parameters": {"body": body},
        "reversibility": "irreversible",
    }


def ticket(idempotency_key="id-1", fence=1, request_digest="sha256:request"):
    return DispatchTicket(
        reservation_id="reservation-1", permit_id="permit-1", campaign_id="campaign-1",
        action_digest="sha256:action", request_digest=request_digest,
        resource_key="sms-resource", idempotency_key=idempotency_key,
        fencing_token=fence, containment_epoch=0,
    )


class SMSSandboxTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "provider.sqlite"
        self.provider = SandboxSMSProvider(self.path, allowed_recipients={"+15551234567"}, allowed_resources={"lead-123"})

    def test_simulates_exact_sms_without_network(self):
        response = self.provider.invoke(action(), ticket())
        self.assertEqual(response["status"], "accepted")
        found = self.provider.query("id-1")
        self.assertEqual(found["effect"], action())
        self.assertEqual(found["request_digest"], "sha256:request")

    def test_idempotency_survives_restart(self):
        first = self.provider.invoke(action(), ticket())
        restarted = SandboxSMSProvider(self.path, allowed_recipients={"+15551234567"}, allowed_resources={"lead-123"})
        second = restarted.invoke(action(), ticket())
        self.assertEqual(first["provider_id"], second["provider_id"])
        self.assertTrue(second["idempotent_replay"])

    def test_message_mutation_on_replay_is_rejected(self):
        self.provider.invoke(action(), ticket())
        with self.assertRaises(SMSBoundaryError):
            self.provider.invoke(action(body="Different text"), ticket())

    def test_denies_outside_recipient(self):
        with self.assertRaises(SMSBoundaryError):
            self.provider.invoke(action(recipient="+15557654321"), ticket())

    def test_denies_scheme_and_transport_mutation(self):
        changed = copy.deepcopy(action())
        changed["destination"]["scheme"] = "https"
        with self.assertRaises(SMSBoundaryError):
            self.provider.invoke(changed, ticket())
        changed = copy.deepcopy(action())
        changed["parameters"]["webhook_url"] = "https://example.com"
        with self.assertRaises(SMSBoundaryError):
            self.provider.invoke(changed, ticket())

    def test_denies_unapproved_resource_and_sender_injection(self):
        changed = action()
        changed["destination"]["resource"] = "lead-other"
        with self.assertRaises(SMSBoundaryError):
            self.provider.invoke(changed, ticket())
        changed = action()
        changed["parameters"]["sender_id"] = "AnotherCompany"
        with self.assertRaises(SMSBoundaryError):
            self.provider.invoke(changed, ticket())
        with self.assertRaises(SMSBoundaryError):
            self.provider.invoke(action(body="hidden\rcontrol"), ticket())

    def test_fencing_monotonicity_is_preserved(self):
        self.provider.invoke(action(), ticket())
        stale = self.provider.invoke(action(), ticket(idempotency_key="id-2", fence=1))
        self.assertEqual(stale["status"], "stale_fence")
        self.assertIsNone(self.provider.query("id-2"))


if __name__ == "__main__":
    unittest.main()
