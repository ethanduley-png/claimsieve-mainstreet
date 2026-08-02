from __future__ import annotations

import copy
import unittest

from claimsieve_ref.fixtures import keypairs
from claimsieve_ref.ledger import Ledger


class LedgerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.keys = keypairs()
        self.ledger = Ledger("proposal", self.keys["proposal"])
        self.ledger.append("trace-1", "PROPOSAL_SUBMITTED", {"proposal_id": "p1"})
        self.ledger.append("trace-2", "PROPOSAL_SUBMITTED", {"proposal_id": "p2"})
        self.public = {self.keys["proposal"].key_id: self.keys["proposal"].public}

    def test_valid_chain(self) -> None:
        self.assertEqual(Ledger.verify(self.ledger.records, self.public, "proposal"), [])

    def test_payload_tampering_detected(self) -> None:
        records = copy.deepcopy(self.ledger.records)
        records[0]["payload"]["proposal_id"] = "evil"
        errors = Ledger.verify(records, self.public, "proposal")
        self.assertTrue(any("payload hash" in error or "signature" in error for error in errors))

    def test_deletion_detected(self) -> None:
        records = [copy.deepcopy(self.ledger.records[1])]
        errors = Ledger.verify(records, self.public, "proposal")
        self.assertTrue(any("sequence mismatch" in error or "previous hash" in error for error in errors))

    def test_reordering_detected(self) -> None:
        records = list(reversed(copy.deepcopy(self.ledger.records)))
        errors = Ledger.verify(records, self.public, "proposal")
        self.assertGreater(len(errors), 0)

    def test_wrong_writer_key_detected(self) -> None:
        errors = Ledger.verify(self.ledger.records, {self.keys["proposal"].key_id: self.keys["evidence"].public}, "proposal")
        self.assertTrue(any("signature invalid" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
