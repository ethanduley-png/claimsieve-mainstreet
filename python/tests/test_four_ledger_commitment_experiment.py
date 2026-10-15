from __future__ import annotations

import copy
import unittest

from claimsieve_ref.canonical import digest
from claimsieve_ref.fixtures import keypairs
from claimsieve_ref.ledger import Ledger


class FourLedgerCommitmentExperimentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.keys = keypairs()
        self.evidence = {
            "schema_version": "claimsieve.ablation.evidence.v1",
            "subject": "lead-123",
            "sequence": 10,
            "verified": True,
            "blob": "x" * 8192,
        }
        self.evidence_digest = digest(self.evidence)
        self.ledger = Ledger("evidence", self.keys["evidence"])
        self.ledger.append(
            "trace-commitment",
            "EVIDENCE_RECORDED",
            {
                "artifact_digest": self.evidence_digest,
                "storage": "content-addressed",
            },
        )
        self.public = {self.keys["evidence"].key_id: self.keys["evidence"].public}

    def test_commitment_record_chain_verifies(self) -> None:
        self.assertEqual(Ledger.verify(self.ledger.records, self.public, "evidence"), [])

    def test_commitment_record_tampering_detected(self) -> None:
        records = copy.deepcopy(self.ledger.records)
        records[0]["payload"]["artifact_digest"] = digest({"evil": True})
        errors = Ledger.verify(records, self.public, "evidence")
        self.assertTrue(any("payload hash" in error or "signature" in error for error in errors))

    def test_retrieved_artifact_matches_commitment_exactly(self) -> None:
        committed = self.ledger.records[0]["payload"]["artifact_digest"]
        self.assertEqual(committed, digest(self.evidence))

    def test_substituted_artifact_fails_commitment(self) -> None:
        changed = copy.deepcopy(self.evidence)
        changed["verified"] = False
        committed = self.ledger.records[0]["payload"]["artifact_digest"]
        self.assertNotEqual(committed, digest(changed))

    def test_four_writer_keys_remain_distinct(self) -> None:
        key_ids = {
            self.keys[name].key_id
            for name in ("proposal", "evidence", "decision", "execution")
        }
        raw_keys = {
            self.keys[name].public.raw
            for name in ("proposal", "evidence", "decision", "execution")
        }
        self.assertEqual(len(key_ids), 4)
        self.assertEqual(len(raw_keys), 4)


if __name__ == "__main__":
    unittest.main()
