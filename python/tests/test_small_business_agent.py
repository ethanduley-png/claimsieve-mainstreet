import unittest

from small_business_agent import ActionRisk, Intent, plan_intent
from small_business_agent.registry import CAPABILITIES


class SmallBusinessAgentTests(unittest.TestCase):
    def test_every_consequential_capability_requires_claimsieve(self):
        consequential = [cap for cap in CAPABILITIES if cap.consequential]
        self.assertGreater(len(consequential), 0)
        self.assertTrue(all(cap.requires_claimsieve for cap in consequential))

    def test_high_risk_capabilities_require_human_approval(self):
        high_risk = {
            ActionRisk.FINANCIAL,
            ActionRisk.LEGAL_COMPLIANCE,
            ActionRisk.EMPLOYMENT,
            ActionRisk.HEALTH_SAFETY,
            ActionRisk.CREDENTIAL_SECURITY,
            ActionRisk.IRREVERSIBLE_HIGH_IMPACT,
        }
        for capability in CAPABILITIES:
            if capability.risk in high_risk and capability.consequential:
                self.assertTrue(
                    capability.requires_human_approval,
                    capability.capability_id,
                )

    def test_broad_founder_request_starts_with_command_center(self):
        plan = plan_intent(
            Intent(
                text="Help me everywhere and tell me what needs my attention today",
                tenant_id="tenant-test",
                principal_id="founder",
            )
        )
        self.assertEqual(plan.items[0].capability_id, "founder_daily_brief")
        self.assertFalse(plan.items[0].consequential)

    def test_refund_request_is_governed(self):
        plan = plan_intent(
            Intent(
                text="Refund this customer and respond to their complaint",
                tenant_id="tenant-test",
                principal_id="founder",
            )
        )
        ids = {item.capability_id for item in plan.items}
        self.assertIn("issue_refund", ids)
        refund = next(item for item in plan.items if item.capability_id == "issue_refund")
        self.assertTrue(refund.requires_claimsieve)
        self.assertTrue(refund.requires_human_approval)

    def test_money_movement_is_never_direct(self):
        plan = plan_intent(
            Intent(
                text="Pay the vendor invoice from our bank account",
                tenant_id="tenant-test",
                principal_id="founder",
            )
        )
        money = [item for item in plan.items if item.capability_id == "move_money"]
        self.assertEqual(len(money), 1)
        self.assertTrue(money[0].consequential)
        self.assertTrue(money[0].requires_claimsieve)
        self.assertTrue(money[0].requires_human_approval)

    def test_wire_command_is_governed_even_without_payment_keyword(self):
        plan = plan_intent(
            Intent(
                text="Please wire 500 dollars to the supplier",
                tenant_id="tenant-test",
                principal_id="founder",
            )
        )
        money = next(item for item in plan.items if item.capability_id == "move_money")
        self.assertTrue(money.requires_claimsieve)
        self.assertTrue(money.requires_human_approval)

    def test_security_access_change_is_human_gated(self):
        plan = plan_intent(
            Intent(
                text="Grant admin access to the new employee",
                tenant_id="tenant-test",
                principal_id="founder",
            )
        )
        items = [item for item in plan.items if item.capability_id == "change_access_or_credentials"]
        self.assertEqual(len(items), 1)
        self.assertTrue(items[0].requires_human_approval)
        self.assertTrue(items[0].requires_claimsieve)

    def test_imperative_email_is_governed_send_not_draft(self):
        plan = plan_intent(
            Intent(
                text="Email Bob and tell him the order is ready",
                tenant_id="tenant-test",
                principal_id="founder",
            )
        )
        ids = {item.capability_id for item in plan.items}
        self.assertIn("send_external_message", ids)
        self.assertNotIn("draft_external_message", ids)
        send = next(item for item in plan.items if item.capability_id == "send_external_message")
        self.assertTrue(send.requires_claimsieve)

    def test_explicit_draft_email_stays_non_executing(self):
        plan = plan_intent(
            Intent(
                text="Draft an email to Bob about the order",
                tenant_id="tenant-test",
                principal_id="founder",
            )
        )
        ids = {item.capability_id for item in plan.items}
        self.assertIn("draft_external_message", ids)
        self.assertNotIn("send_external_message", ids)

    def test_membership_cancellation_is_governed_and_human_gated(self):
        plan = plan_intent(
            Intent(
                text="Please cancel this customer's membership today",
                tenant_id="tenant-test",
                principal_id="founder",
            )
        )
        item = next(item for item in plan.items if item.capability_id == "cancel_customer_service")
        self.assertTrue(item.requires_claimsieve)
        self.assertTrue(item.requires_human_approval)

    def test_destructive_delete_is_governed_and_human_gated(self):
        plan = plan_intent(
            Intent(
                text="Delete all old customer records",
                tenant_id="tenant-test",
                principal_id="founder",
            )
        )
        item = next(item for item in plan.items if item.capability_id == "destructive_data_change")
        self.assertTrue(item.requires_claimsieve)
        self.assertTrue(item.requires_human_approval)
        self.assertEqual(item.risk, ActionRisk.IRREVERSIBLE_HIGH_IMPACT)

    def test_health_safety_request_is_governed_and_human_gated(self):
        plan = plan_intent(
            Intent(
                text="Customer has chest pain and asks if it is safe to work out",
                tenant_id="tenant-test",
                principal_id="founder",
            )
        )
        item = next(item for item in plan.items if item.capability_id == "health_safety_escalation")
        self.assertEqual(item.risk, ActionRisk.HEALTH_SAFETY)
        self.assertTrue(item.requires_claimsieve)
        self.assertTrue(item.requires_human_approval)

    def test_keyword_matching_uses_token_boundaries(self):
        plan = plan_intent(
            Intent(
                text="Review our repayment assumptions",
                tenant_id="tenant-test",
                principal_id="founder",
            )
        )
        self.assertNotIn("move_money", {item.capability_id for item in plan.items})

    def test_unknown_request_defaults_to_non_consequential_triage(self):
        plan = plan_intent(
            Intent(
                text="I have no idea where to start",
                tenant_id="tenant-test",
                principal_id="founder",
            )
        )
        self.assertEqual(len(plan.items), 1)
        self.assertEqual(plan.items[0].capability_id, "founder_daily_brief")
        self.assertFalse(plan.requires_claimsieve)

    def test_invalid_intent_fails_closed(self):
        with self.assertRaises(ValueError):
            plan_intent(Intent(text="", tenant_id="tenant-test", principal_id="founder"))


if __name__ == "__main__":
    unittest.main()
