from __future__ import annotations

import unittest

from tax_notice_durable_demo import run_demo


class TaxNoticeDurableDemoTest(unittest.TestCase):
    def test_successful_synthetic_tax_submission(self) -> None:
        result = run_demo("success")
        self.assertEqual(result["decision"], "ALLOW")
        self.assertEqual(result["reconciliation"], "CONFIRMED_SUCCESS")
        self.assertFalse(result["live_portal_access"])
        self.assertFalse(result["automatic_retry_allowed"])
        self.assertTrue(result["journal_verified"])

    def test_ambiguous_tax_submission_remains_unknown(self) -> None:
        result = run_demo("timeout_before_commit")
        self.assertEqual(result["reconciliation"], "OUTCOME_UNKNOWN")
        self.assertFalse(result["automatic_retry_allowed"])


if __name__ == "__main__":
    unittest.main()
