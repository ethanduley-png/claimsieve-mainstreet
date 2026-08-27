from datetime import date, timedelta
import math
import unittest

from small_business_agent.brain import BusinessProfile, BusinessSignal, BusinessSnapshot, merge_signals
from small_business_agent.brief import build_founder_brief
from small_business_agent.inbox import InboxMessage, triage_message


class SmallBusinessBrainTests(unittest.TestCase):
    def profile(self):
        return BusinessProfile(
            tenant_id="tenant-aj",
            legal_name="AJ Fitness LLC",
            display_name="AJ Fitness",
            business_type="gym",
            timezone="America/Indiana/Indianapolis",
            locations=("Elkhart",),
            owner_ids=("aj",),
        )

    def test_brief_separates_founder_agent_and_watch(self):
        today = date(2026, 8, 13)
        snapshot = BusinessSnapshot(
            profile=self.profile(),
            as_of=today,
            signals=(
                BusinessSignal("s1", "refund", "Customer requests $149 refund", 4, "crm", amount=149.0),
                BusinessSignal("s2", "lead_followup", "Lead has waited 23 hours", 3, "crm"),
                BusinessSignal("s3", "website_note", "About page is old", 1, "website"),
            ),
            stale_sources=("bank-feed",),
        )
        brief = build_founder_brief(snapshot)
        self.assertEqual([x.signal_id for x in brief.needs_founder], ["s1"])
        self.assertEqual([x.signal_id for x in brief.agent_can_handle], ["s2"])
        self.assertEqual([x.signal_id for x in brief.watch], ["s3"])
        self.assertIn("stale source: bank-feed", brief.data_warnings)

    def test_unknown_severity_four_signal_escalates_to_founder(self):
        today = date(2026, 8, 13)
        snapshot = BusinessSnapshot(
            profile=self.profile(),
            as_of=today,
            signals=(BusinessSignal("s4", "unclassified_exception", "Unknown material exception", 4, "new-connector"),),
        )
        brief = build_founder_brief(snapshot)
        self.assertEqual([x.signal_id for x in brief.needs_founder], ["s4"])
        self.assertEqual(brief.agent_can_handle, ())

    def test_due_date_drives_why_now(self):
        today = date(2026, 8, 13)
        snapshot = BusinessSnapshot(
            profile=self.profile(),
            as_of=today,
            signals=(BusinessSignal("tax", "legal_deadline", "State filing due", 4, "compliance", due_date=today + timedelta(days=2)),),
        )
        brief = build_founder_brief(snapshot)
        self.assertEqual(brief.needs_founder[0].why_now, "due in 2 day(s)")

    def test_signal_merge_rejects_conflicting_duplicate(self):
        a = BusinessSignal("same", "lead_followup", "Lead A", 3, "crm")
        b = BusinessSignal("same", "lead_followup", "Lead B", 3, "crm")
        with self.assertRaises(ValueError):
            merge_signals((a,), (b,))

    def test_non_finite_amount_fails_closed(self):
        with self.assertRaises(ValueError):
            BusinessSignal("bad", "refund", "Bad amount", 4, "crm", amount=math.nan).validate()

    def test_non_finite_metric_fails_closed(self):
        snapshot = BusinessSnapshot(
            profile=self.profile(),
            as_of=date(2026, 8, 13),
            metrics={"revenue": math.inf},
        )
        with self.assertRaises(ValueError):
            snapshot.validate()

    def test_inbox_refund_is_governed(self):
        triage = triage_message(
            InboxMessage("m1", "email", "customer@example.com", "Refund", "Please refund my membership charge."),
            tenant_id="tenant-aj",
            principal_id="agent-mainstreet",
        )
        self.assertTrue(triage.requires_claimsieve)

    def test_invalid_empty_message_fails_closed(self):
        with self.assertRaises(ValueError):
            triage_message(InboxMessage("m2", "email", "x@example.com", "", ""), "tenant", "agent")


if __name__ == "__main__":
    unittest.main()
