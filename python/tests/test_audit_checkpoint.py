from __future__ import annotations

import copy
import unittest

from claimsieve_ref.audit_checkpoint import (
    AuditCheckpointError,
    issue_checkpoint,
    journal_head,
    verify_checkpoint,
)
from claimsieve_ref.canonical import digest
from claimsieve_ref.crypto import KeyPair


def event(previous: str, sequence: int) -> dict:
    unsigned = {
        "event_sequence": sequence,
        "event_type": "ACTION",
        "object_id": "reservation",
        "payload": {"sequence": sequence},
        "previous_hash": previous,
    }
    return {**unsigned, "event_hash": digest(unsigned)}


class AuditCheckpointTests(unittest.TestCase):
    def setUp(self) -> None:
        self.auditor = KeyPair.from_seed("external-auditor", bytes([19]) * 32)
        self.attacker = KeyPair.from_seed("attacker", bytes([22]) * 32)
        self.events = [event("GENESIS", 1)]
        self.events.append(event(self.events[-1]["event_hash"], 2))
        self.checkpoint = issue_checkpoint(self.events, self.auditor)
        self.external_pin = digest(self.checkpoint)

    def verify(self, events=None, checkpoint=None, pin=None):
        return verify_checkpoint(
            self.events if events is None else events,
            self.checkpoint if checkpoint is None else checkpoint,
            self.auditor.public,
            externally_pinned_digest=self.external_pin if pin is None else pin,
        )

    def test_external_key_and_pinned_digest_verify(self):
        self.assertTrue(self.verify())

    def test_no_external_pin_fails_closed(self):
        with self.assertRaises(AuditCheckpointError):
            self.verify(pin="")

    def test_truncated_journal_detected(self):
        with self.assertRaises(AuditCheckpointError):
            self.verify(events=self.events[:-1])

    def test_modified_rehashed_journal_detected_by_pin(self):
        corrupted = copy.deepcopy(self.events)
        corrupted[0]["payload"]["sequence"] = 99
        corrupted[0]["event_hash"] = digest({k: v for k, v in corrupted[0].items() if k != "event_hash"})
        corrupted[1]["previous_hash"] = corrupted[0]["event_hash"]
        corrupted[1]["event_hash"] = digest({k: v for k, v in corrupted[1].items() if k != "event_hash"})
        with self.assertRaises(AuditCheckpointError):
            self.verify(events=corrupted)

    def test_sequence_gap_detected(self):
        corrupted = copy.deepcopy(self.events)
        corrupted[1]["event_sequence"] = 7
        corrupted[1]["event_hash"] = digest({k: v for k, v in corrupted[1].items() if k != "event_hash"})
        with self.assertRaises(AuditCheckpointError):
            journal_head(corrupted)

    def test_attacker_signing_not_independent_auditor(self):
        forged = issue_checkpoint(self.events, self.attacker)
        with self.assertRaises(AuditCheckpointError):
            self.verify(checkpoint=forged, pin=digest(forged))

    def test_checkpoint_history_pins_previous_prefix(self):
        first = issue_checkpoint(self.events[:1], self.auditor)
        next_checkpoint = issue_checkpoint(self.events, self.auditor, previous=first)
        self.assertTrue(verify_checkpoint(
            self.events, next_checkpoint, self.auditor.public,
            externally_pinned_digest=digest(next_checkpoint), previous=first
        ))
        with self.assertRaises(AuditCheckpointError):
            verify_checkpoint(
                self.events, next_checkpoint, self.auditor.public,
                externally_pinned_digest=digest(next_checkpoint)
            )


if __name__ == "__main__":
    unittest.main()
