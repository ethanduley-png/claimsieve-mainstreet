from __future__ import annotations

import copy
import unittest

from claimsieve_ref.canonical import digest
from claimsieve_ref.fixtures import keypairs
from claimsieve_ref.unified_audit import UnifiedAuditLog, default_record_roles


class UnifiedAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.keys = keypairs()
        self.role_keys = {
            "proposal": {self.keys["proposal"].key_id},
            "evidence": {self.keys["evidence"].key_id},
            "decision": {self.keys["decision"].key_id},
            "execution": {self.keys["execution"].key_id},
        }
        self.public = {
            self.keys[name].key_id: self.keys[name].public
            for name in ("proposal", "evidence", "decision", "execution", "witness")
        }
        self.roles = default_record_roles()
        self.evidence = {"consent": True, "sequence": 10, "blob": "x" * 8192}
        self.log = UnifiedAuditLog()
        self.log.append(
            trace_id="trace-1",
            record_type="PROPOSAL_SUBMITTED",
            writer_role="proposal",
            writer=self.keys["proposal"],
            payload={"proposal_id": "p1", "destination": "sms:+15551234567"},
        )
        self.log.append(
            trace_id="trace-1",
            record_type="EVIDENCE_RECORDED",
            writer_role="evidence",
            writer=self.keys["evidence"],
            payload_digest=digest(self.evidence),
        )
        self.log.append(
            trace_id="trace-1",
            record_type="DECISION_RECORDED",
            writer_role="decision",
            writer=self.keys["decision"],
            payload={"decision": "ALLOW", "evidence_root": digest(self.evidence)},
        )
        self.log.append(
            trace_id="trace-1",
            record_type="EXECUTOR_RECEIPT",
            writer_role="execution",
            writer=self.keys["execution"],
            payload={"status": "submitted", "provider_id": "provider-1"},
        )

    def verify(self, records: list[dict]) -> list[str]:
        return UnifiedAuditLog.verify(
            records,
            keys=self.public,
            role_keys=self.role_keys,
            record_roles=self.roles,
        )

    def test_valid_chain(self) -> None:
        self.assertEqual(self.verify(self.log.records), [])

    def test_payload_tampering_detected(self) -> None:
        records = copy.deepcopy(self.log.records)
        records[0]["payload"]["destination"] = "sms:+19999999999"
        errors = self.verify(records)
        self.assertTrue(any("payload digest" in error or "signature" in error for error in errors))

    def test_commitment_tampering_detected(self) -> None:
        records = copy.deepcopy(self.log.records)
        records[1]["payload_digest"] = digest({"consent": False})
        errors = self.verify(records)
        self.assertTrue(any("signature" in error or "record hash" in error for error in errors))

    def test_deletion_detected(self) -> None:
        records = copy.deepcopy(self.log.records)
        del records[1]
        errors = self.verify(records)
        self.assertTrue(any("sequence mismatch" in error or "previous hash" in error for error in errors))

    def test_reordering_detected(self) -> None:
        records = copy.deepcopy(self.log.records)
        records[1], records[2] = records[2], records[1]
        self.assertGreater(len(self.verify(records)), 0)

    def test_cross_role_forgery_detected(self) -> None:
        forged = UnifiedAuditLog()
        forged.append(
            trace_id="trace-evil",
            record_type="DECISION_RECORDED",
            writer_role="proposal",
            writer=self.keys["proposal"],
            payload={"decision": "ALLOW"},
        )
        errors = self.verify(forged.records)
        self.assertTrue(any("writer role mismatch" in error for error in errors))

    def test_evidence_writer_cannot_forge_execution(self) -> None:
        forged = UnifiedAuditLog()
        forged.append(
            trace_id="trace-evil",
            record_type="EXECUTOR_RECEIPT",
            writer_role="evidence",
            writer=self.keys["evidence"],
            payload={"status": "submitted"},
        )
        errors = self.verify(forged.records)
        self.assertTrue(any("writer role mismatch" in error for error in errors))

    def test_correct_role_label_with_wrong_key_detected(self) -> None:
        forged = UnifiedAuditLog()
        forged.append(
            trace_id="trace-evil",
            record_type="DECISION_RECORDED",
            writer_role="decision",
            writer=self.keys["proposal"],
            payload={"decision": "ALLOW"},
        )
        errors = self.verify(forged.records)
        self.assertTrue(any("writer key not allowed" in error for error in errors))

    def test_unknown_record_type_fails_closed(self) -> None:
        forged = UnifiedAuditLog()
        forged.append(
            trace_id="trace-evil",
            record_type="MAGIC_ALLOW",
            writer_role="decision",
            writer=self.keys["decision"],
            payload={"decision": "ALLOW"},
        )
        errors = self.verify(forged.records)
        self.assertTrue(any("unknown record type" in error for error in errors))

    def test_committed_payload_replay_is_exact(self) -> None:
        record = self.log.records[1]
        self.assertTrue(UnifiedAuditLog.verify_committed_payload(record, self.evidence))
        changed = copy.deepcopy(self.evidence)
        changed["consent"] = False
        self.assertFalse(UnifiedAuditLog.verify_committed_payload(record, changed))

    def test_witnessed_checkpoint_accepts_exact_head(self) -> None:
        checkpoint = self.log.checkpoint(self.keys["witness"])
        errors = UnifiedAuditLog.verify_checkpoint(
            self.log.records,
            checkpoint,
            keys=self.public,
            allowed_witness_key_ids={self.keys["witness"].key_id},
        )
        self.assertEqual(errors, [])

    def test_witnessed_checkpoint_detects_suffix_truncation(self) -> None:
        checkpoint = self.log.checkpoint(self.keys["witness"])
        truncated = copy.deepcopy(self.log.records[:-1])
        errors = UnifiedAuditLog.verify_checkpoint(
            truncated,
            checkpoint,
            keys=self.public,
            allowed_witness_key_ids={self.keys["witness"].key_id},
        )
        self.assertTrue(any("record count" in error or "head hash" in error for error in errors))

    def test_untrusted_checkpoint_witness_rejected(self) -> None:
        checkpoint = self.log.checkpoint(self.keys["proposal"])
        errors = UnifiedAuditLog.verify_checkpoint(
            self.log.records,
            checkpoint,
            keys=self.public,
            allowed_witness_key_ids={self.keys["witness"].key_id},
        )
        self.assertTrue(any("witness key not allowed" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
